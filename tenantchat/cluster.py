"""K-means clustering for user/device risk segmentation and finding grouping."""

from __future__ import annotations

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from tenantchat.models import CheckResult, CheckStatus, Severity, UserCluster


class Clusterer:
    """
    K-means clustering applied to tenant assessment data.

    Three applications:
      1. User risk segmentation — actionable population clusters
      2. Finding root cause grouping — related issues surfaced together
      3. Blast radius change clustering — sequence related changes
    """

    # ── User risk segmentation ────────────────────────────────────────────

    def cluster_users(
        self,
        users: list[dict],
        mfa_data: list[dict],
        devices: list[dict],
        n_clusters: int = 4,
    ) -> list[UserCluster]:
        """
        Segment users into risk clusters based on security attributes.

        Feature vector per user:
          0 — MFA registered (1/0)
          1 — MFA capable / phishing-resistant (1/0)
          2 — Has compliant device (1/0)
          3 — Account enabled (1/0)
          4 — Is licensed (1/0)
          5 — Is guest (1/0)
        """
        if not users:
            return []

        # Build MFA lookup
        mfa_lookup: dict[str, dict] = {
            m.get("userPrincipalName", ""): m
            for m in mfa_data
        }

        # Build compliant device lookup by UPN
        compliant_upns: set[str] = {
            d.get("userPrincipalName", "")
            for d in devices
            if d.get("complianceState") == "compliant"
        }

        # Build feature matrix
        feature_rows = []
        user_tokens  = []

        for user in users:
            upn  = user.get("userPrincipalName", "")
            mfa  = mfa_lookup.get(upn, {})

            features = [
                1 if mfa.get("isMfaRegistered", False)  else 0,
                1 if mfa.get("isMfaCapable", False)      else 0,
                1 if upn in compliant_upns                else 0,
                1 if user.get("accountEnabled", True)     else 0,
                1 if user.get("assignedLicenses")         else 0,
                1 if user.get("userType") == "Guest"      else 0,
            ]
            feature_rows.append(features)
            user_tokens.append(upn)

        if len(feature_rows) < n_clusters:
            n_clusters = max(1, len(feature_rows))

        X = np.array(feature_rows, dtype=float)

        try:
            scaler  = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            km      = KMeans(
                n_clusters=n_clusters,
                random_state=42,
                n_init=10,
            )
            labels  = km.fit_predict(X_scaled)
        except Exception:
            # Fallback — single cluster if K-means fails
            labels = np.zeros(len(feature_rows), dtype=int)

        # Build cluster summaries
        clusters: dict[int, list[int]] = {}
        for idx, label in enumerate(labels):
            clusters.setdefault(int(label), []).append(idx)

        result = []
        for cluster_id, indices in clusters.items():
            cluster_features = X[indices]
            avg              = cluster_features.mean(axis=0)

            mfa_rate       = avg[0]
            phish_rate     = avg[1]
            compliant_rate = avg[2]
            enabled_rate   = avg[3]
            guest_rate     = avg[5]

            # Characterise the cluster
            characteristics = []
            action          = ""
            risk_level      = "low"

            if mfa_rate < 0.1:
                characteristics.append("No MFA registered")
                risk_level = "critical"
                action     = (
                    "Run MFA registration campaign immediately. "
                    "Enforce MFA CA policy after registration complete."
                )
            elif mfa_rate < 0.5:
                characteristics.append("Low MFA registration")
                risk_level = "high"
                action     = (
                    "Targeted MFA registration nudge for this group."
                )
            elif phish_rate < 0.3:
                characteristics.append("SMS/voice MFA only")
                risk_level = "medium"
                action     = (
                    "Upgrade to phishing-resistant MFA "
                    "(Authenticator app or FIDO2)."
                )

            if compliant_rate < 0.3:
                characteristics.append("Most devices non-compliant")
                risk_level = risk_level if risk_level == "critical" else "high"
                action     = action or (
                    "Remediate device compliance before enforcing "
                    "compliant device CA policy."
                )

            if guest_rate > 0.5:
                characteristics.append("Primarily guest accounts")
                action = action or (
                    "Review guest access — ensure appropriate "
                    "expiry and access reviews configured."
                )

            if not characteristics:
                characteristics.append("Well-configured")
                action = "No immediate action required. Monitor for changes."

            # Generate cluster label
            label_str = self._cluster_label(
                mfa_rate, phish_rate, compliant_rate, guest_rate
            )

            result.append(UserCluster(
                cluster_id=cluster_id,
                label=label_str,
                risk_level=risk_level,
                user_count=len(indices),
                characteristics=characteristics,
                recommended_action=action,
                user_tokens=[user_tokens[i] for i in indices],
            ))

        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        result.sort(key=lambda c: risk_order.get(c.risk_level, 4))

        return result

    def _cluster_label(
        self,
        mfa_rate:       float,
        phish_rate:     float,
        compliant_rate: float,
        guest_rate:     float,
    ) -> str:
        if mfa_rate < 0.1:
            return "No MFA — Immediate action"
        if mfa_rate < 0.5:
            return "Partial MFA — High risk"
        if phish_rate < 0.3:
            return "Weak MFA — Upgrade needed"
        if compliant_rate < 0.3:
            return "MFA OK — Device gap"
        if guest_rate > 0.5:
            return "Guest accounts — Review needed"
        return "Well configured — Monitor"

    # ── Finding grouping ─────────────────────────────────────────────────

    def group_findings(
        self,
        findings: list[CheckResult],
    ) -> list[list[CheckResult]]:
        """
        Group related findings by root cause using K-means.

        Feature vector per finding:
          0 — Severity score (critical=4, high=3, medium=2, low=1)
          1 — Is identity domain (1/0)
          2 — Is device domain (1/0)
          3 — Is CA policy related (1/0)
          4 — Is MFA related (1/0)
          5 — Drift score (0-1, inverted so 1 = worst)
        """
        failed = [
            f for f in findings
            if f.status in (CheckStatus.FAIL, CheckStatus.PARTIAL)
        ]
        if not failed:
            return []

        severity_map = {
            Severity.CRITICAL: 4,
            Severity.HIGH:     3,
            Severity.MEDIUM:   2,
            Severity.LOW:      1,
            Severity.INFO:     0,
        }

        feature_rows = []
        for f in failed:
            title_lower = f.title.lower()
            features = [
                severity_map.get(f.severity, 1),
                1 if any(w in title_lower for w in
                         ["user", "admin", "identity", "mfa", "pim",
                          "conditional access", "sign-in"]) else 0,
                1 if any(w in title_lower for w in
                         ["device", "intune", "compliant",
                          "enrol", "managed"]) else 0,
                1 if "conditional access" in title_lower
                     or "ca policy" in title_lower else 0,
                1 if "mfa" in title_lower
                     or "authentication" in title_lower else 0,
                round(1 - f.drift_score, 2),
            ]
            feature_rows.append(features)

        n = min(3, len(feature_rows))
        if n < 2:
            return [failed]

        X = np.array(feature_rows, dtype=float)
        try:
            scaler   = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            km       = KMeans(n_clusters=n, random_state=42, n_init=10)
            labels   = km.fit_predict(X_scaled)
        except Exception:
            return [failed]

        groups: dict[int, list[CheckResult]] = {}
        for idx, label in enumerate(labels):
            groups.setdefault(int(label), []).append(failed[idx])

        # Sort each group by severity
        sorted_groups = []
        for group in groups.values():
            group.sort(
                key=lambda f: severity_map.get(f.severity, 0),
                reverse=True,
            )
            sorted_groups.append(group)

        # Sort groups by worst finding in each
        sorted_groups.sort(
            key=lambda g: severity_map.get(g[0].severity, 0),
            reverse=True,
        )

        return sorted_groups

    # ── Change clustering ────────────────────────────────────────────────

    def cluster_changes(
        self,
        findings: list[CheckResult],
    ) -> dict[str, list[CheckResult]]:
        """
        Group findings by change type to sequence remediation.

        Returns dict with keys:
          'immediate'  — safe to apply now, low blast radius
          'staged'     — apply after preparation, medium blast radius
          'planned'    — require project planning, high blast radius
        """
        immediate = []
        staged    = []
        planned   = []

        high_blast_keywords = [
            "legacy auth", "mfa", "compliant device",
            "pim", "global admin",
        ]
        low_blast_keywords = [
            "audit", "retention", "password expir",
            "stale", "report",
        ]

        for f in findings:
            if f.status not in (CheckStatus.FAIL, CheckStatus.PARTIAL):
                continue
            title_lower = f.title.lower()

            if any(kw in title_lower for kw in high_blast_keywords):
                planned.append(f)
            elif any(kw in title_lower for kw in low_blast_keywords):
                immediate.append(f)
            else:
                staged.append(f)

        return {
            "immediate": immediate,
            "staged":    staged,
            "planned":   planned,
        }
