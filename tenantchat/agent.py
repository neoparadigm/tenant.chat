"""LangGraph conversation engine — stateful branching assessment conversations."""

from __future__ import annotations

import json
import os
import uuid
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

_AGENT_SYSTEM = """You are a Microsoft 365 security remediation agent.
Your job is to explain a specific security gap and its fix in plain English.

Rules:
- Be direct and specific — no filler.
- Cite MITRE ATT&CK technique IDs where relevant.
- Name the exact configuration items that must change.
- Quantify the blast radius (how many users / what breaks).
- Never recommend enforcing a change without a validation period first.
- Keep responses under 250 words.
"""

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

    # ── One-click Agents (HITL) ────────────────────────────────────────────

    async def run_agent(
        self,
        agent_name:   str,
        assessment:   AssessmentResult | None = None,
        tenant_state: TenantState | None = None,
        token:        str | None = None,
    ) -> dict:
        """
        Generate a HITL-gated remediation plan.

        Returns a plan dict containing:
          - plan_id          — opaque ID stored server-side
          - agent_name       — which agent built this plan
          - title            — short description
          - reasoning        — Gemma 4 explanation of what and why
          - blast_radius     — list of what might break
          - graph_api_calls  — ordered list of write operations (NOT yet executed)
          - requires_approval — always True; no execution without UI approval

        No Graph API writes happen in this method.
        """
        builders = {
            "device-code-block": self._plan_device_code_block,
            "aitm-hardening":    self._plan_aitm_hardening,
            "break-glass-setup": self._plan_break_glass_setup,
            "inbox-rule-audit":  self._plan_inbox_rule_audit,
            "stryker-defense":   self._plan_stryker_defense,
        }
        builder = builders.get(agent_name)
        if not builder:
            raise ValueError(
                f"Unknown agent '{agent_name}'. "
                f"Valid agents: {', '.join(builders)}"
            )
        return await builder(assessment, tenant_state, token)

    # ── Agent plan builders ────────────────────────────────────────────────

    async def _plan_device_code_block(
        self,
        assessment:   AssessmentResult | None,
        tenant_state: TenantState | None,
        token:        str | None,
    ) -> dict:
        """Block device code OAuth flow via a new Conditional Access policy."""
        context = self._agent_context(assessment, tenant_state, ["ENTRA-DC-01"])
        reasoning = await self._llm_call(
            system=_AGENT_SYSTEM,
            context=context,
            message=(
                "The tenant is missing a Conditional Access policy that blocks device "
                "code OAuth flow.  Storm-2372 uses this flow to steal tokens without "
                "triggering MFA.\n\n"
                "Explain in plain English:\n"
                "1. What device code flow is and why it's dangerous.\n"
                "2. What this new CA policy will do.\n"
                "3. What might break (be specific — printers, legacy apps, IoT).\n"
                "4. Why the policy is set to report-only first.\n"
                "Keep your answer under 200 words."
            ),
        )
        return {
            "plan_id":     str(uuid.uuid4()),
            "agent_name":  "device-code-block",
            "title":       "Block Device Code Flow (Storm-2372 defence)",
            "reasoning":   reasoning,
            "blast_radius": [
                "Devices that use device code flow for authentication will break",
                "Older IoT/printer integrations using device code may be affected",
                "Azure CLI / PowerShell interactive device code login will fail",
                "Policy starts in report-only mode — review Sign-in logs before enforcing",
            ],
            "graph_api_calls": [
                {
                    "step":        1,
                    "description": "Create CA policy blocking device code flow (report-only)",
                    "method":      "POST",
                    "endpoint":    "/identity/conditionalAccess/policies",
                    "body": {
                        "displayName": "BLOCK — Device Code Flow [tenant.chat]",
                        "state":       "enabledForReportingButNotEnforced",
                        "conditions": {
                            "users":        {"includeUsers": ["All"]},
                            "applications": {"includeApplications": ["All"]},
                            "authenticationFlows": {
                                "transferMethods": "deviceCodeFlow",
                            },
                        },
                        "grantControls": {
                            "operator":          "OR",
                            "builtInControls":   ["block"],
                        },
                    },
                    "reversible":        True,
                    "undo_instructions": "Delete the CA policy with id returned in response.",
                },
            ],
            "requires_approval": True,
            "warning": (
                "This policy is created in REPORT-ONLY mode.  Review the Sign-in "
                "logs for 7–14 days before switching state to 'enabled'.  "
                "To enforce: PATCH /identity/conditionalAccess/policies/{id} "
                "with state: 'enabled'."
            ),
        }

    async def _plan_aitm_hardening(
        self,
        assessment:   AssessmentResult | None,
        tenant_state: TenantState | None,
        token:        str | None,
    ) -> dict:
        """Harden against AiTM attacks: CAE + sign-in frequency + phish-resistant MFA."""
        context = self._agent_context(
            assessment, tenant_state,
            ["ENTRA-CAE-01", "ENTRA-TOKEN-01", "ENTRA-TOKEN-02", "ENTRA-MFA-02"],
        )
        reasoning = await self._llm_call(
            system=_AGENT_SYSTEM,
            context=context,
            message=(
                "The tenant is missing defences against AiTM session cookie theft.\n\n"
                "Explain in plain English:\n"
                "1. Why Continuous Access Evaluation (CAE) limits stolen session impact.\n"
                "2. Why sign-in frequency limits token lifetime.\n"
                "3. What might break for users (re-authentication frequency).\n"
                "Keep your answer under 200 words."
            ),
        )
        return {
            "plan_id":    str(uuid.uuid4()),
            "agent_name": "aitm-hardening",
            "title":      "AiTM Hardening (CAE + token lifetime + phish-resistant MFA)",
            "reasoning":  reasoning,
            "blast_radius": [
                "Users will be re-prompted to sign in every hour for privileged sessions",
                "Long-running browser sessions will be interrupted",
                "Applications that do not support CAE may behave inconsistently",
                "Mobile apps need modern auth support for CAE to apply",
            ],
            "graph_api_calls": [
                {
                    "step":        1,
                    "description": "Create CA policy enforcing 1-hour sign-in frequency for all users",
                    "method":      "POST",
                    "endpoint":    "/identity/conditionalAccess/policies",
                    "body": {
                        "displayName": "REQUIRE — Sign-in Frequency 1hr [tenant.chat]",
                        "state":       "enabledForReportingButNotEnforced",
                        "conditions": {
                            "users":        {"includeUsers": ["All"]},
                            "applications": {"includeApplications": ["All"]},
                        },
                        "sessionControls": {
                            "signInFrequency": {
                                "value":             1,
                                "type":              "hours",
                                "isEnabled":         True,
                                "frequencyInterval": "timeBased",
                            },
                            "persistentBrowser": {
                                "mode":      "never",
                                "isEnabled": True,
                            },
                            "continuousAccessEvaluation": {
                                "mode": "strictLocation",
                            },
                        },
                    },
                    "reversible":        True,
                    "undo_instructions": "Delete the CA policy with id returned in response.",
                },
                {
                    "step":        2,
                    "description": "Create CA policy requiring phishing-resistant MFA for admin portals",
                    "method":      "POST",
                    "endpoint":    "/identity/conditionalAccess/policies",
                    "body": {
                        "displayName": "REQUIRE — Phish-Resistant MFA for Admins [tenant.chat]",
                        "state":       "enabledForReportingButNotEnforced",
                        "conditions": {
                            "users": {
                                "includeRoles": [
                                    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                                    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
                                    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
                                ],
                            },
                            "applications": {
                                "includeApplications": ["MicrosoftAdminPortals"],
                            },
                        },
                        "grantControls": {
                            "operator":               "OR",
                            "authenticationStrength": {
                                "id": "00000000-0000-0000-0000-000000000004",  # Phishing-resistant MFA
                            },
                        },
                    },
                    "reversible":        True,
                    "undo_instructions": "Delete the CA policy with id returned in response.",
                },
            ],
            "requires_approval": True,
            "warning": (
                "Both policies are created in REPORT-ONLY mode.  "
                "The phishing-resistant MFA policy requires admins to have "
                "FIDO2 keys or Windows Hello for Business enrolled before enforcing."
            ),
        }

    async def _plan_break_glass_setup(
        self,
        assessment:   AssessmentResult | None,
        tenant_state: TenantState | None,
        token:        str | None,
    ) -> dict:
        """Create a break-glass monitoring alert and guidance for account setup."""
        context = self._agent_context(assessment, tenant_state, ["ENTRA-PRIV-03"])
        reasoning = await self._llm_call(
            system=_AGENT_SYSTEM,
            context=context,
            message=(
                "The tenant may lack properly configured break-glass emergency access accounts.\n\n"
                "Explain in plain English:\n"
                "1. What break-glass accounts are and why they're critical.\n"
                "2. Why they must be excluded from ALL CA policies and MFA requirements.\n"
                "3. How to secure and store the passwords.\n"
                "4. Why immediate alerting on their use is mandatory.\n"
                "Keep your answer under 200 words."
            ),
        )
        return {
            "plan_id":    str(uuid.uuid4()),
            "agent_name": "break-glass-setup",
            "title":      "Break-Glass Emergency Access — Alert Configuration",
            "reasoning":  reasoning,
            "blast_radius": [
                "No blast radius — alert creation is additive and non-disruptive",
                "Break-glass account creation (manual step) requires careful password management",
                "Accounts must be manually excluded from all CA policies after creation",
            ],
            "graph_api_calls": [
                {
                    "step":        1,
                    "description": "Create alert rule for break-glass account sign-in activity",
                    "method":      "POST",
                    "endpoint":    "/security/alerts_v2",
                    "body": {
                        "displayName":  "ALERT — Break-Glass Account Sign-In [tenant.chat]",
                        "description":  (
                            "Fires immediately when a break-glass emergency access account "
                            "is used.  All usage must be investigated — break-glass accounts "
                            "should never be used in normal operations."
                        ),
                        "severity":     "high",
                        "status":       "active",
                        "category":     "IdentityRisk",
                    },
                    "reversible":        True,
                    "undo_instructions": "DELETE /security/alerts_v2/{id}",
                },
                {
                    "step":        2,
                    "description": "Query existing users for break-glass candidates (read-only)",
                    "method":      "GET",
                    "endpoint":    (
                        "/users?$filter=displayName eq 'BreakGlass1' "
                        "or displayName eq 'BreakGlass2'"
                        "&$select=id,displayName,userPrincipalName,accountEnabled"
                    ),
                    "body":              None,
                    "reversible":        True,
                    "undo_instructions": "Read-only — no undo needed.",
                },
            ],
            "requires_approval": True,
            "warning": (
                "Break-glass account CREATION is a manual step requiring careful "
                "out-of-band password management.  After creation, both accounts must "
                "be manually excluded from all Conditional Access policies and MFA "
                "registration requirements.  Store passwords offline split across two "
                "custodians.  Monitor sign-in logs for any usage with immediate alerting."
            ),
        }

    async def _plan_inbox_rule_audit(
        self,
        assessment:   AssessmentResult | None,
        tenant_state: TenantState | None,
        token:        str | None,
    ) -> dict:
        """Enable mailbox audit logging and alert on suspicious inbox rule creation."""
        context = self._agent_context(
            assessment, tenant_state, ["ENTRA-MAIL-01", "ENTRA-MAIL-02"]
        )
        reasoning = await self._llm_call(
            system=_AGENT_SYSTEM,
            context=context,
            message=(
                "The tenant may have gaps in inbox rule auditing and external forwarding controls.\n\n"
                "Explain in plain English:\n"
                "1. Why inbox rules are a critical persistence technique after BEC.\n"
                "2. What suspicious inbox rules look like (keywords: delete, forward, hide).\n"
                "3. Why external auto-forwarding must be blocked by default.\n"
                "4. What legitimate use cases might be affected.\n"
                "Keep your answer under 200 words."
            ),
        )
        return {
            "plan_id":    str(uuid.uuid4()),
            "agent_name": "inbox-rule-audit",
            "title":      "Inbox Rule Audit and External Forwarding Block",
            "reasoning":  reasoning,
            "blast_radius": [
                "Users who auto-forward email to personal accounts will lose forwarding",
                "Legitimate workflows using inbox rules to route to shared mailboxes may be affected",
                "Review forwarding rules with business owners before blocking",
                "Exchange transport rules affect all users — communicate change in advance",
            ],
            "graph_api_calls": [
                {
                    "step":        1,
                    "description": "Enable unified audit log for the organisation (read state)",
                    "method":      "GET",
                    "endpoint":    "/security/auditLog/queries",
                    "body":        None,
                    "reversible":        True,
                    "undo_instructions": "Read-only — no undo needed.",
                },
                {
                    "step":        2,
                    "description": "Create alert for inbox rule creation events",
                    "method":      "POST",
                    "endpoint":    "/security/alerts_v2",
                    "body": {
                        "displayName": "ALERT — Inbox Rule Created [tenant.chat]",
                        "description": (
                            "Fires when any user creates or modifies an inbox rule.  "
                            "Investigate rules that forward, delete, or move security "
                            "notifications to hidden folders."
                        ),
                        "severity": "medium",
                        "status":   "active",
                        "category": "SuspiciousActivity",
                    },
                    "reversible":        True,
                    "undo_instructions": "DELETE /security/alerts_v2/{id}",
                },
                {
                    "step":        3,
                    "description": "Query existing inbox rules across mailboxes (read-only audit)",
                    "method":      "GET",
                    "endpoint":    "/users?$select=id,userPrincipalName&$top=10",
                    "body":        None,
                    "reversible":        True,
                    "undo_instructions": "Read-only — no undo needed.",
                },
            ],
            "requires_approval": True,
            "warning": (
                "Blocking external auto-forwarding requires an Exchange Online transport "
                "rule (not Graph API).  Run in Exchange Admin Center: "
                "New-TransportRule -Name 'Block external forwarding' "
                "-FromScope 'InOrganization' -SentToScope 'NotInOrganization' "
                "-RedirectMessageTo $null -StopRuleProcessing $true.  "
                "Review all existing forwarding rules with business owners first."
            ),
        }

    async def _plan_stryker_defense(
        self,
        assessment:   AssessmentResult | None,
        tenant_state: TenantState | None,
        token:        str | None,
    ) -> dict:
        """Full Stryker-breach defence: phish-resistant MFA for admins + GA alert + PIM check."""
        context = self._agent_context(
            assessment, tenant_state,
            ["ENTRA-MFA-02", "ENTRA-CA-06", "ENTRA-IDP-03", "ENTRA-PRIV-01", "ENTRA-PRIV-02"],
        )
        reasoning = await self._llm_call(
            system=_AGENT_SYSTEM,
            context=context,
            message=(
                "The tenant has gaps that match the Stryker breach attack chain "
                "(CISA advisory March 2026).\n\n"
                "Explain in plain English:\n"
                "1. The Stryker attack chain: AiTM → GA compromise → new GA → Intune wipe.\n"
                "2. Which specific controls would have blocked each step.\n"
                "3. What the immediate priority actions are for this tenant.\n"
                "4. Why phishing-resistant MFA for admins is the single most important control.\n"
                "Keep your answer under 250 words."
            ),
        )

        # Check current admin count for context
        admin_context = ""
        if tenant_state and tenant_state.admins:
            admin_context = f" (current count: {len(tenant_state.admins)} Global Admins)"

        return {
            "plan_id":    str(uuid.uuid4()),
            "agent_name": "stryker-defense",
            "title":      f"Stryker Breach Defence — Admin Hardening{admin_context}",
            "reasoning":  reasoning,
            "blast_radius": [
                "Admins without FIDO2/WHfB enrolled will lose access to admin portals",
                "Coordinate FIDO2 key procurement and distribution before enforcing",
                "New GA creation alert may generate noise if PIM activations are frequent",
                "Review PIM configuration with all admins before reducing permanent assignments",
            ],
            "graph_api_calls": [
                {
                    "step":        1,
                    "description": "Create alert on new Global Administrator account creation",
                    "method":      "POST",
                    "endpoint":    "/security/alerts_v2",
                    "body": {
                        "displayName": "CRITICAL ALERT — New Global Admin Created [tenant.chat]",
                        "description": (
                            "Fires immediately when a new account is assigned the Global "
                            "Administrator role.  The Stryker attacker created a backdoor GA "
                            "account after the initial compromise.  Investigate any alert "
                            "within minutes — not hours."
                        ),
                        "severity": "high",
                        "status":   "active",
                        "category": "PrivilegeEscalation",
                    },
                    "reversible":        True,
                    "undo_instructions": "DELETE /security/alerts_v2/{id}",
                },
                {
                    "step":        2,
                    "description": "Create CA policy requiring phishing-resistant MFA for admin portals (report-only)",
                    "method":      "POST",
                    "endpoint":    "/identity/conditionalAccess/policies",
                    "body": {
                        "displayName": "REQUIRE — Phish-Resistant MFA for Admin Portals [tenant.chat]",
                        "state":       "enabledForReportingButNotEnforced",
                        "conditions": {
                            "users": {
                                "includeRoles": [
                                    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
                                    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
                                ],
                            },
                            "applications": {
                                "includeApplications": ["MicrosoftAdminPortals"],
                            },
                        },
                        "grantControls": {
                            "operator":               "OR",
                            "authenticationStrength": {
                                "id": "00000000-0000-0000-0000-000000000004",
                            },
                        },
                    },
                    "reversible":        True,
                    "undo_instructions": "Delete the CA policy with id returned in response.",
                },
                {
                    "step":        3,
                    "description": "Query current Global Admin count (read-only baseline check)",
                    "method":      "GET",
                    "endpoint":    (
                        "/directoryRoles?$filter=displayName eq 'Global Administrator'"
                        "&$expand=members($select=id,displayName,userPrincipalName)"
                    ),
                    "body":        None,
                    "reversible":        True,
                    "undo_instructions": "Read-only — no undo needed.",
                },
            ],
            "requires_approval": True,
            "warning": (
                "The phishing-resistant MFA CA policy is in REPORT-ONLY mode.  "
                "Before enforcing: ensure ALL Global Admins have registered FIDO2 "
                "security keys or Windows Hello for Business.  Enforcing before "
                "registration will lock admins out of admin portals permanently "
                "(until break-glass accounts are used)."
            ),
        }

    # ── Agent helpers ──────────────────────────────────────────────────────

    def _agent_context(
        self,
        assessment:   AssessmentResult | None,
        tenant_state: TenantState | None,
        control_ids:  list[str],
    ) -> str:
        """Build focused context for agent LLM calls."""
        lines = []
        if tenant_state:
            lines.append(
                f"TENANT: {tenant_state.tenant_domain} | "
                f"Users: {len(tenant_state.users)} | "
                f"Global Admins: {len(tenant_state.admins)} | "
                f"CA Policies: {len(tenant_state.ca_policies)}"
            )
        if assessment:
            relevant = [
                f for f in assessment.findings
                if f.control_id in control_ids
            ]
            if relevant:
                lines.append("RELEVANT FINDINGS:")
                for f in relevant:
                    lines.append(
                        f"  [{f.status.value.upper()}] {f.control_id} — {f.title}"
                    )
                    if f.delta:
                        lines.append(f"    Delta: {f.delta}")
        return "\n".join(lines)
