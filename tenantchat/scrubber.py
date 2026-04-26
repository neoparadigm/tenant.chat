"""PII scrubbing via Microsoft Presidio — anonymises tenant data before LLM."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

_TOKEN_MAP_PATH = Path.home() / ".tenantchat" / "token_map.json"


class Scrubber:
    """
    Anonymises PII in tenant data before any LLM call.

    Scrubs:  UPNs, display names, email addresses, IPs, device names
    Keeps:   Policy names, group names, setting values, counts, dates,
             configuration GUIDs — these are needed for actionable output.
    """

    def __init__(self) -> None:
        self._analyzer  = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()
        self._token_map: dict[str, str] = self._load_token_map()

    # ── Public API ────────────────────────────────────────────────────────

    def scrub_text(self, text: str) -> str:
        """Scrub PII from a plain text string."""
        if not text:
            return text

        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS"],
        )

        # Also scrub UPN patterns manually (user@domain.com)
        text = self._scrub_upns(text)

        if results:
            text = self._anonymizer.anonymize(
                text=text, analyzer_results=results
            ).text

        return text

    def scrub_user(self, user: dict) -> dict:
        """Scrub PII fields from a user object."""
        scrubbed = dict(user)
        for field in ("userPrincipalName", "displayName", "mail",
                      "otherMails", "proxyAddresses"):
            if field in scrubbed:
                scrubbed[field] = self._tokenise(
                    str(scrubbed[field]), prefix="USER"
                )
        return scrubbed

    def scrub_device(self, device: dict) -> dict:
        """Scrub PII fields from a device object."""
        scrubbed = dict(device)
        if "userPrincipalName" in scrubbed:
            scrubbed["userPrincipalName"] = self._tokenise(
                str(scrubbed["userPrincipalName"]), prefix="USER"
            )
        if "deviceName" in scrubbed:
            scrubbed["deviceName"] = self._tokenise(
                str(scrubbed["deviceName"]), prefix="DEVICE"
            )
        return scrubbed

    def scrub_list(
        self,
        items: list[dict],
        scrub_type: str = "user",
    ) -> list[dict]:
        """Scrub a list of user or device objects."""
        fn = self.scrub_user if scrub_type == "user" else self.scrub_device
        return [fn(item) for item in items]

    def scrub_finding_context(self, context: str) -> str:
        """Scrub PII from a finding explanation before sending to LLM."""
        return self.scrub_text(context)

    def restore_token(self, token: str) -> str:
        """Reverse-lookup a token to its original value (local only)."""
        reverse = {v: k for k, v in self._token_map.items()}
        return reverse.get(token, token)

    # ── Internal helpers ─────────────────────────────────────────────────

    def _tokenise(self, value: str, prefix: str = "ENTITY") -> str:
        """Replace a PII value with a consistent token."""
        if not value or value in ("", "None", "null"):
            return value
        if value in self._token_map:
            return self._token_map[value]
        short = hashlib.md5(value.encode()).hexdigest()[:6].upper()
        token = f"{prefix}_{short}"
        self._token_map[value] = token
        self._save_token_map()
        return token

    def _scrub_upns(self, text: str) -> str:
        """Scrub UPN patterns (user@domain.com) from text."""
        upn_pattern = re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        )
        def replace_upn(match: re.Match) -> str:
            return self._tokenise(match.group(), prefix="USER")
        return upn_pattern.sub(replace_upn, text)

    def _load_token_map(self) -> dict[str, str]:
        _TOKEN_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
        if _TOKEN_MAP_PATH.exists():
            try:
                return json.loads(_TOKEN_MAP_PATH.read_text())
            except Exception:
                return {}
        return {}

    def _save_token_map(self) -> None:
        _TOKEN_MAP_PATH.write_text(
            json.dumps(self._token_map, indent=2)
        )
