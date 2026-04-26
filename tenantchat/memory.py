"""Cross-session memory via Mem0 — persists assessment context between sessions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

console     = Console()
MEMORY_PATH = Path.home() / ".tenantchat" / "memory.json"


class Memory:
    """
    Persistent cross-session memory for tenant.chat.

    Stores:
      - Assessment history (findings, scores, dates)
      - Decisions made (what was fixed, what was deferred)
      - Conversation summaries
      - Tenant-specific context

    Uses Mem0 when available, falls back to local JSON storage.
    """

    def __init__(self, tenant_id: str = "") -> None:
        self.tenant_id  = tenant_id
        self._store: dict[str, Any] = self._load()
        self._mem0      = None
        self._init_mem0()

    def _init_mem0(self) -> None:
        """Initialise Mem0 if available."""
        try:
            from mem0 import Memory as Mem0Memory
            self._mem0 = Mem0Memory()
        except Exception:
            pass

    # ── Assessment history ────────────────────────────────────────────────

    def save_assessment(
        self,
        tenant_id:    str,
        score:        float,
        critical:     int,
        high:         int,
        frameworks:   list[str],
        finding_count: int,
    ) -> None:
        """Save an assessment result to memory."""
        key     = f"assessment_{tenant_id}"
        history = self._store.get(key, [])
        history.append({
            "assessed_at":   datetime.now(tz=timezone.utc).isoformat(),
            "score":         score,
            "critical":      critical,
            "high":          high,
            "frameworks":    frameworks,
            "finding_count": finding_count,
        })
        # Keep last 20 assessments
        self._store[key] = history[-20:]
        self._save()

        # Also store in Mem0 if available
        if self._mem0:
            try:
                self._mem0.add(
                    f"Assessment for tenant {tenant_id}: "
                    f"score {score}/100, {critical} critical findings, "
                    f"{high} high findings across {frameworks}",
                    user_id=tenant_id,
                )
            except Exception:
                pass

    def get_assessment_history(
        self,
        tenant_id: str,
    ) -> list[dict]:
        """Get assessment history for a tenant."""
        return self._store.get(f"assessment_{tenant_id}", [])

    def get_score_trend(self, tenant_id: str) -> str:
        """Return a plain-text score trend description."""
        history = self.get_assessment_history(tenant_id)
        if len(history) < 2:
            return "First assessment — no trend data yet."

        latest   = history[-1]["score"]
        previous = history[-2]["score"]
        delta    = latest - previous

        if delta > 5:
            return (
                f"Improving ↑ Score increased from "
                f"{previous} to {latest} (+{delta:.1f})"
            )
        elif delta < -5:
            return (
                f"Declining ↓ Score decreased from "
                f"{previous} to {latest} ({delta:.1f})"
            )
        else:
            return (
                f"Stable → Score {latest} "
                f"(was {previous} last assessment)"
            )

    # ── Decisions ────────────────────────────────────────────────────────

    def save_decision(
        self,
        tenant_id:   str,
        control_id:  str,
        decision:    str,
        notes:       str = "",
    ) -> None:
        """
        Record a remediation decision.
        decision: 'fixed' | 'deferred' | 'accepted_risk' | 'wont_fix'
        """
        key      = f"decisions_{tenant_id}"
        decisions = self._store.get(key, {})
        decisions[control_id] = {
            "decision":  decision,
            "notes":     notes,
            "recorded_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        self._store[key] = decisions
        self._save()

        if self._mem0:
            try:
                self._mem0.add(
                    f"Decision for {control_id} in tenant {tenant_id}: "
                    f"{decision}. Notes: {notes}",
                    user_id=tenant_id,
                )
            except Exception:
                pass

    def get_decision(
        self,
        tenant_id:  str,
        control_id: str,
    ) -> dict | None:
        """Get the recorded decision for a specific control."""
        decisions = self._store.get(f"decisions_{tenant_id}", {})
        return decisions.get(control_id)

    def get_all_decisions(self, tenant_id: str) -> dict:
        """Get all recorded decisions for a tenant."""
        return self._store.get(f"decisions_{tenant_id}", {})

    # ── Conversation context ─────────────────────────────────────────────

    def save_conversation_summary(
        self,
        tenant_id: str,
        summary:   str,
    ) -> None:
        """Save a summary of the current conversation."""
        key      = f"conv_{tenant_id}"
        summaries = self._store.get(key, [])
        summaries.append({
            "summary":    summary,
            "saved_at":  datetime.now(tz=timezone.utc).isoformat(),
        })
        self._store[key] = summaries[-10:]
        self._save()

    def get_recent_context(self, tenant_id: str) -> str:
        """Get recent conversation context as plain text."""
        summaries = self._store.get(f"conv_{tenant_id}", [])
        if not summaries:
            return ""
        recent = summaries[-3:]
        return "\n".join(s["summary"] for s in recent)

    def search_memory(
        self,
        tenant_id: str,
        query:     str,
    ) -> str:
        """Search Mem0 memory for relevant context."""
        if not self._mem0:
            return self.get_recent_context(tenant_id)
        try:
            results = self._mem0.search(query, user_id=tenant_id)
            if results:
                return "\n".join(
                    r.get("memory", "") for r in results[:3]
                )
        except Exception:
            pass
        return self.get_recent_context(tenant_id)

    # ── Tenant notes ─────────────────────────────────────────────────────

    def save_note(
        self,
        tenant_id: str,
        note:      str,
    ) -> None:
        """Save a freeform note about a tenant."""
        key   = f"notes_{tenant_id}"
        notes = self._store.get(key, [])
        notes.append({
            "note":      note,
            "saved_at": datetime.now(tz=timezone.utc).isoformat(),
        })
        self._store[key] = notes[-50:]
        self._save()

    def get_notes(self, tenant_id: str) -> list[dict]:
        """Get all notes for a tenant."""
        return self._store.get(f"notes_{tenant_id}", [])

    # ── Storage ──────────────────────────────────────────────────────────

    def _load(self) -> dict:
        MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if MEMORY_PATH.exists():
            try:
                return json.loads(MEMORY_PATH.read_text())
            except Exception:
                return {}
        return {}

    def _save(self) -> None:
        try:
            MEMORY_PATH.write_text(
                json.dumps(self._store, indent=2)
            )
        except Exception:
            pass
