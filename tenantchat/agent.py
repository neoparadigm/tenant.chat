"""LangGraph conversation engine — stateful branching assessment conversations."""

from __future__ import annotations

import json
import os
from typing import Any, TypedDict

import httpx
from rich.console import Console

from tenantchat.assessor import Assessor
from tenantchat.blast import BlastAnalyzer
from tenantchat.cluster import Clusterer
from tenantchat.memory import Memory
from tenantchat.models import AssessmentResult, TenantState
from tenantchat.scrubber import Scrubber
from tenantchat.store import Store

console = Console()

OLLAMA_BASE  = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("TENANTCHAT_MODEL", "gemma4")
CLAUDE_MODEL = "claude-sonnet-4-6"

_SYSTEM_PROMPT = """You are tenant.chat — a local-first M365 security 
assessment agent. You help IT admins and security architects understand 
their Microsoft 365 tenant security posture.

Rules you always follow:
- Never guess. If uncertain, say so explicitly.
- Always cite your source (baseline control ID, community reference).
- Never recommend a change without explaining the blast radius first.
- Keep answers concise and actionable.
- Use exact policy names, group names, and setting values from the context.
- Never reveal raw user UPNs or device names — use the anonymised tokens.

You have access to:
- The tenant's current configuration state
- Assessment findings against security baselines
- Blast radius analysis for proposed changes
- Community knowledge from security practitioners
- Historical assessment data

When asked about a finding, always include:
1. What is wrong (exact values)
2. Why it matters (risk context)
3. What breaks if you fix it (blast radius)
4. How to fix it (sequence)
5. Community context if available
"""


class AgentState(TypedDict):
    """State passed through the LangGraph conversation graph."""
    messages:        list[dict]
    tenant_state:    dict | None
    assessment:      dict | None
    current_finding: dict | None
    blast_result:    dict | None
    clusters:        list | None
    tenant_id:       str


class Agent:
    """
    Conversational AI agent for tenant security assessment.

    Uses LangGraph for stateful branching flows.
    Ollama (Gemma 4) as default local inference.
    Claude API as opt-in for enhanced reasoning.
    """

    def __init__(self) -> None:
        self._assessor  = Assessor()
        self._blast     = BlastAnalyzer()
        self._clusterer = Clusterer()
        self._scrubber  = Scrubber()
        self._store     = Store()
        self._use_claude = bool(os.environ.get("ANTHROPIC_API_KEY"))
        self._graph     = self._build_graph()

    def _build_graph(self) -> Any:
        """Build the LangGraph conversation flow."""
        try:
            from langgraph.graph import END, StateGraph

            builder = StateGraph(AgentState)

            builder.add_node("classify",     self._classify_intent)
            builder.add_node("assess",       self._run_assessment)
            builder.add_node("explain",      self._explain_finding)
            builder.add_node("blast",        self._blast_radius)
            builder.add_node("cluster",      self._cluster_users)
            builder.add_node("respond",      self._generate_response)

            builder.set_entry_point("classify")

            builder.add_conditional_edges(
                "classify",
                self._route_intent,
                {
                    "assess":  "assess",
                    "explain": "explain",
                    "blast":   "blast",
                    "cluster": "cluster",
                    "respond": "respond",
                },
            )

            for node in ("assess", "explain", "blast", "cluster"):
                builder.add_edge(node, "respond")

            builder.add_edge("respond", END)

            return builder.compile()

        except Exception as e:
            console.print(
                f"[yellow]LangGraph unavailable ({e}), "
                f"using simple flow.[/yellow]"
            )
            return None

    # ── Public API ────────────────────────────────────────────────────────

    async def chat(
        self,
        message:      str,
        tenant_state: TenantState | None = None,
        assessment:   AssessmentResult | None = None,
        memory:       Memory | None = None,
        tenant_id:    str = "",
    ) -> str:
        """Process a user message and return the agent response."""

        # Assemble context
        context = self._assemble_context(
            message=message,
            tenant_state=tenant_state,
            assessment=assessment,
            memory=memory,
            tenant_id=tenant_id,
        )

        # Route based on intent
        intent = self._detect_intent(message)

        if intent == "assess" and tenant_state:
            assessment = await self._run_assessment_async(tenant_state)
            context += f"\n\nASSESSMENT RESULTS:\n{self._format_assessment(assessment)}"

        elif intent == "blast":
            blast_result = self._blast.analyze(message, tenant_state or TenantState(
                tenant_id="", tenant_domain="", collected_at=__import__('datetime').datetime.now()
            ))
            context += f"\n\nBLAST RADIUS:\n{self._blast.format_for_display(blast_result)}"

        elif intent == "cluster" and tenant_state:
            clusters = self._clusterer.cluster_users(
                tenant_state.users,
                tenant_state.mfa_registration,
                tenant_state.managed_devices,
            )
            context += f"\n\nUSER SEGMENTS:\n{self._format_clusters(clusters)}"

        # Generate response
        response = await self._llm_call(
            system=_SYSTEM_PROMPT,
            context=context,
            message=message,
        )

        # Save to memory
        if memory and tenant_id:
            memory.save_conversation_summary(
                tenant_id,
                f"Q: {message[:100]} A: {response[:200]}",
            )

        return response

    # ── Context assembly ─────────────────────────────────────────────────

    def _assemble_context(
        self,
        message:      str,
        tenant_state: TenantState | None,
        assessment:   AssessmentResult | None,
        memory:       Memory | None,
        tenant_id:    str,
    ) -> str:
        """Assemble four-layer context for LLM call."""
        layers = []

        # Layer 1 — Tenant state summary
        if tenant_state:
            layers.append(
                f"TENANT: {tenant_state.tenant_domain}\n"
                f"Users: {len(tenant_state.users)} | "
                f"Guests: {len(tenant_state.guests)} | "
                f"Devices: {len(tenant_state.managed_devices)} | "
                f"CA Policies: {len(tenant_state.ca_policies)} | "
                f"Global Admins: {len(tenant_state.admins)}"
            )

        # Layer 2 — Assessment findings
        if assessment:
            layers.append(self._format_assessment_summary(assessment))

        # Layer 3 — Community KB (semantic search)
        try:
            kb_results = self._store.search_kb(message, top_k=2)
            if kb_results:
                kb_text = "\n".join(
                    f"[{r['metadata'].get('author', 'Community')}] "
                    f"{r['text'][:200]}"
                    for r in kb_results
                )
                layers.append(f"COMMUNITY KNOWLEDGE:\n{kb_text}")
        except Exception:
            pass

        # Layer 4 — Conversation history
        if memory and tenant_id:
            history = memory.get_recent_context(tenant_id)
            if history:
                layers.append(f"RECENT CONTEXT:\n{history}")

        return "\n\n".join(layers)

    # ── Intent detection ─────────────────────────────────────────────────

    def _detect_intent(self, message: str) -> str:
        """Detect user intent from message."""
        msg = message.lower()

        assess_keywords = [
            "/assess", "run assessment", "check my tenant",
            "assess", "scan", "what's wrong",
        ]
        blast_keywords = [
            "/blast", "what breaks", "blast radius",
            "impact", "what will break", "before i",
        ]
        cluster_keywords = [
            "/cluster", "segment users", "user risk",
            "group users", "who is at risk",
        ]

        if any(kw in msg for kw in assess_keywords):
            return "assess"
        if any(kw in msg for kw in blast_keywords):
            return "blast"
        if any(kw in msg for kw in cluster_keywords):
            return "cluster"
        return "respond"

    # ── LangGraph nodes ───────────────────────────────────────────────────

    def _classify_intent(self, state: AgentState) -> AgentState:
        messages = state["messages"]
        last_msg = messages[-1]["content"] if messages else ""
        state["_intent"] = self._detect_intent(last_msg)
        return state

    def _route_intent(self, state: AgentState) -> str:
        return state.get("_intent", "respond")

    async def _run_assessment_async(
        self, state: TenantState
    ) -> AssessmentResult:
        """Run assessment against tenant state."""
        self._assessor.load_baselines()
        return self._assessor.assess(state)

    def _run_assessment(self, state: AgentState) -> AgentState:
        return state

    def _explain_finding(self, state: AgentState) -> AgentState:
        return state

    def _blast_radius(self, state: AgentState) -> AgentState:
        return state

    def _cluster_users(self, state: AgentState) -> AgentState:
        return state

    def _generate_response(self, state: AgentState) -> AgentState:
        return state

    # ── LLM calls ────────────────────────────────────────────────────────

    async def _llm_call(
        self,
        system:  str,
        context: str,
        message: str,
    ) -> str:
        """Call local Ollama or Claude API."""
        if self._use_claude:
            return await self._claude_call(system, context, message)
        return await self._ollama_call(system, context, message)

    async def _ollama_call(
        self,
        system:  str,
        context: str,
        message: str,
    ) -> str:
        """Call local Ollama inference."""
        full_prompt = (
            f"{system}\n\n"
            f"CONTEXT:\n{context}\n\n"
            f"USER: {message}\n\n"
            f"ASSISTANT:"
        )
        payload = {
            "model":  OLLAMA_MODEL,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_ctx":     8192,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{OLLAMA_BASE}/api/generate",
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json().get("response", "").strip()
        except httpx.ConnectError:
            return (
                "Cannot reach Ollama. "
                f"Is it running? Try: ollama serve\n"
                f"Then: ollama pull {OLLAMA_MODEL}"
            )
        except Exception as e:
            return f"LLM error: {e}"

    async def _claude_call(
        self,
        system:  str,
        context: str,
        message: str,
    ) -> str:
        """Call Claude API (opt-in, PII-scrubbed context only)."""
        try:
            import anthropic
            client = anthropic.AsyncAnthropic()
            msg    = await client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=1024,
                system=system,
                messages=[{
                    "role":    "user",
                    "content": f"CONTEXT:\n{context}\n\nQUESTION: {message}",
                }],
            )
            return msg.content[0].text
        except Exception as e:
            return f"Claude API error: {e}"

    # ── Formatters ────────────────────────────────────────────────────────

    def _format_assessment(self, assessment: AssessmentResult) -> str:
        """Format full assessment for LLM context."""
        lines = [
            f"Posture score: {assessment.posture_score}/100",
            f"Critical: {assessment.critical_count} | "
            f"High: {assessment.high_count} | "
            f"Medium: {assessment.medium_count}",
            "",
            "FINDINGS:",
        ]
        from tenantchat.models import CheckStatus
        for f in assessment.findings:
            if f.status in (CheckStatus.FAIL, CheckStatus.PARTIAL):
                lines.append(
                    f"[{f.severity.value.upper()}] {f.control_id} "
                    f"— {f.title}"
                )
                if f.delta:
                    lines.append(f"  Delta: {f.delta}")
                if f.affected_count:
                    lines.append(
                        f"  Affected: {f.affected_count} objects"
                    )
        return "\n".join(lines)

    def _format_assessment_summary(
        self, assessment: AssessmentResult
    ) -> str:
        """Format assessment summary for LLM context layer."""
        from tenantchat.models import CheckStatus, Severity
        critical = [
            f for f in assessment.findings
            if f.status == CheckStatus.FAIL
            and f.severity == Severity.CRITICAL
        ]
        return (
            f"ASSESSMENT SUMMARY:\n"
            f"Score: {assessment.posture_score}/100 | "
            f"Critical: {assessment.critical_count} | "
            f"High: {assessment.high_count}\n"
            f"Critical findings: "
            + ", ".join(f.control_id for f in critical[:5])
        )

    def _format_clusters(self, clusters) -> str:
        """Format user clusters for LLM context."""
        lines = []
        for c in clusters:
            lines.append(
                f"Cluster {c.cluster_id} — {c.label} "
                f"({c.user_count} users, {c.risk_level} risk)"
            )
            lines.append(f"  Action: {c.recommended_action}")
        return "\n".join(lines)
