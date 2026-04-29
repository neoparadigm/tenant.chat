"""Baseline comparison and drift detection engine."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console

from tenantchat.embedder import Embedder
from tenantchat.models import (
    AssessmentResult,
    BaselineControl,
    CheckResult,
    CheckStatus,
    CheckType,
    Severity,
    TenantState,
)

console       = Console()
BASELINE_PATH = Path(__file__).parent.parent / "baselines"


class Assessor:
    """
    Runs baseline checks against collected tenant state.

    Three complementary approaches:
      1. Exact checks  — presence, value, threshold, coverage, staleness
      2. Embeddings    — CA policy matrix intent coverage
      3. K-means       — handled by cluster.py on the findings output
    """

    def __init__(self) -> None:
        self._embedder  = Embedder()
        self._controls: list[BaselineControl] = []

    def load_baselines(
        self,
        frameworks: list[str] | None = None,
    ) -> None:
        """Load baseline YAML files from the baselines/ directory."""
        self._controls = []
        paths = list(BASELINE_PATH.rglob("*.yaml"))

        for path in paths:
            try:
                data = yaml.safe_load(path.read_text())
                if not data or "controls" not in data:
                    continue
                framework = data.get("framework", path.stem)
                if frameworks and framework not in frameworks:
                    continue
                for ctrl in data["controls"]:
                    self._controls.append(
                        BaselineControl(
                            control_id=ctrl["control_id"],
                            framework=framework,
                            title=ctrl["title"],
                            description=ctrl.get("description", ""),
                            check_type=CheckType(
                                ctrl.get("check_type", "presence")
                            ),
                            severity=Severity(
                                ctrl.get("severity", "medium")
                            ),
                            effort=ctrl.get("effort", "medium"),
                            graph_endpoint=ctrl.get(
                                "graph_endpoint", ""
                            ),
                            expected=ctrl.get("expected"),
                            blast_radius=ctrl.get("blast_radius", []),
                            community_ref=ctrl.get("community_ref", ""),
                            references=ctrl.get("references", []),
                        )
                    )
            except Exception as e:
                console.print(
                    f"[yellow]Warning:[/yellow] Could not load "
                    f"{path.name}: {e}"
                )

        console.print(
            f"[dim]Loaded {len(self._controls)} baseline controls "
            f"across {len(set(c.framework for c in self._controls))} "
            f"frameworks.[/dim]"
        )

    def assess(self, state: TenantState) -> AssessmentResult:
        """Run all loaded baseline controls against tenant state."""
        if not self._controls:
            self.load_baselines()

        findings: list[CheckResult] = []

        for control in self._controls:
            result = self._run_check(control, state)
            findings.append(result)

        # Calculate posture score
        # PASS=1.0, PARTIAL=0.5, UNKNOWN=0.3, FAIL=0.0
        total    = len(findings)
        weighted = sum(
            1.0 if f.status == CheckStatus.PASS else
            0.5 if f.status == CheckStatus.PARTIAL else
            0.1 if f.status == CheckStatus.UNKNOWN else
            0.0
            for f in findings
        )
        passing  = sum(1 for f in findings if f.status == CheckStatus.PASS)
        score    = round((weighted / total * 100), 1) if total else 0.0

        # Count by severity
        critical = sum(
            1 for f in findings
            if f.status == CheckStatus.FAIL
            and f.severity == Severity.CRITICAL
        )
        high = sum(
            1 for f in findings
            if f.status == CheckStatus.FAIL
            and f.severity == Severity.HIGH
        )
        medium = sum(
            1 for f in findings
            if f.status == CheckStatus.FAIL
            and f.severity == Severity.MEDIUM
        )
        low = sum(
            1 for f in findings
            if f.status == CheckStatus.FAIL
            and f.severity == Severity.LOW
        )

        return AssessmentResult(
            tenant_id=state.tenant_id,
            tenant_domain=state.tenant_domain,
            assessed_at=datetime.now(tz=timezone.utc),
            posture_score=score,
            frameworks=list(
                set(c.framework for c in self._controls)
            ),
            findings=findings,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            pass_count=passing,
            total_controls=total,
        )

    # ── Check runners ────────────────────────────────────────────────────

    def _run_check(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> CheckResult:
        """Route a control to the appropriate check function."""
        try:
            fn = {
                CheckType.PRESENCE:  self._check_presence,
                CheckType.VALUE:     self._check_value,
                CheckType.THRESHOLD: self._check_threshold,
                CheckType.COVERAGE:  self._check_coverage,
                CheckType.STALENESS: self._check_staleness,
            }.get(control.check_type, self._check_unknown)

            return fn(control, state)

        except Exception as e:
            return CheckResult(
                control_id=control.control_id,
                framework=control.framework,
                title=control.title,
                severity=control.severity,
                effort=control.effort,
                status=CheckStatus.UNKNOWN,
                delta=f"Check failed: {e}",
                blast_radius=control.blast_radius,
                community_ref=control.community_ref,
                checked_at=datetime.now(tz=timezone.utc),
            )

    def _check_presence(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> CheckResult:
        """
        Check whether a required configuration exists.
        Uses embeddings for CA policy matrix intent coverage.
        """
        base = self._base_result(control)

        # CA policy checks — use embedding coverage scoring
        if "conditionalAccess" in control.graph_endpoint:
            return self._check_ca_policy_coverage(control, state)

        # Direct collection checks
        collection = self._get_collection(control, state)
        if collection is None:
            base.status = CheckStatus.UNKNOWN
            base.delta  = "Collection not available"
            return base

        if isinstance(control.expected, dict):
            matches = self._filter_objects(collection, control.expected)
            if matches:
                base.status          = CheckStatus.PASS
                base.drift_score     = 1.0
                base.affected_count  = len(matches)
            else:
                base.status          = CheckStatus.FAIL
                base.drift_score     = 0.0
                base.expected        = control.expected
                base.actual          = f"No matching objects found"
                base.delta           = (
                    f"Expected configuration not found in "
                    f"{control.graph_endpoint}"
                )
        return base

    def _check_ca_policy_coverage(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> CheckResult:
        """Score CA policy matrix coverage using embeddings."""
        base = self._base_result(control)

        if not state.ca_policies:
            base.status = CheckStatus.FAIL
            base.actual = "No CA policies found"
            base.delta  = "No Conditional Access policies exist in tenant"
            return base

        requirement = (
            f"{control.title}. {control.description}"
        )
        score, gap_policies = self._embedder.policy_coverage_score(
            requirement, state.ca_policies
        )

        base.drift_score    = score
        base.affected_count = len(state.ca_policies)

        if score >= 0.7:
            base.status = CheckStatus.PASS
        elif score >= 0.4:
            base.status   = CheckStatus.PARTIAL
            base.delta    = (
                f"CA policy coverage score: {score:.0%}. "
                f"{len(gap_policies)} policies have low relevance."
            )
            base.affected_objects = [
                p.get("displayName", "Unknown policy")
                for p in gap_policies
            ]
        else:
            base.status   = CheckStatus.FAIL
            base.delta    = (
                f"CA policy coverage score: {score:.0%}. "
                f"No policy adequately covers this requirement."
            )
            base.affected_objects = [
                p.get("displayName", "Unknown policy")
                for p in state.ca_policies
            ]

        return base

    def _check_value(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> CheckResult:
        """Check whether a specific setting has the expected value."""
        base       = self._base_result(control)
        collection = self._get_collection(control, state)

        if collection is None:
            base.status = CheckStatus.UNKNOWN
            return base

        items  = collection if isinstance(collection, list) else [collection]
        failed = []

        for item in items:
            field    = control.expected.get("field", "") if isinstance(
                control.expected, dict) else ""
            expected = control.expected.get("value") if isinstance(
                control.expected, dict) else control.expected
            actual   = self._get_nested(item, field)

            if actual != expected:
                failed.append({
                    "name":     item.get(
                        "displayName",
                        item.get("id", "unknown")
                    ),
                    "expected": expected,
                    "actual":   actual,
                })

        if not failed:
            base.status      = CheckStatus.PASS
            base.drift_score = 1.0
        else:
            base.status          = CheckStatus.FAIL
            base.drift_score     = 1 - (len(failed) / len(items))
            base.affected_count  = len(failed)
            base.affected_objects = [
                f"{f['name']}: expected {f['expected']}, "
                f"got {f['actual']}"
                for f in failed
            ]
            base.delta = (
                f"{len(failed)} of {len(items)} objects "
                f"have incorrect value for this control"
            )

        return base

    def _check_threshold(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> CheckResult:
        """Check whether a count is within acceptable bounds."""
        base       = self._base_result(control)
        collection = self._get_collection(control, state)

        if collection is None:
            base.status = CheckStatus.UNKNOWN
            return base

        count    = len(collection) if isinstance(collection, list) else 0
        expected = control.expected or {}
        max_val  = expected.get("max")
        min_val  = expected.get("min")

        base.actual         = count
        base.affected_count = count

        if max_val is not None and count > max_val:
            base.status      = CheckStatus.FAIL
            base.drift_score = max(0.0, 1 - ((count - max_val) / max_val))
            base.delta       = (
                f"Found {count}, maximum allowed is {max_val}. "
                f"Excess: {count - max_val}"
            )
            base.affected_objects = [
                item.get(
                    "displayName",
                    item.get("userPrincipalName", str(item.get("id", "")))
                )
                for item in (collection or [])
            ]
        elif min_val is not None and count < min_val:
            base.status      = CheckStatus.FAIL
            base.drift_score = count / min_val if min_val > 0 else 0.0
            base.delta       = (
                f"Found {count}, minimum required is {min_val}"
            )
        else:
            base.status      = CheckStatus.PASS
            base.drift_score = 1.0

        return base

    def _check_coverage(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> CheckResult:
        """
        Check what percentage of a population meets a condition.
        Never binary — always returns a percentage with breakdown.
        """
        base       = self._base_result(control)
        collection = self._get_collection(control, state)

        if not collection:
            base.status = CheckStatus.UNKNOWN
            return base

        condition = control.expected or {}
        field     = condition.get("field", "")
        value     = condition.get("value")
        min_pct   = condition.get("min_percent", 100)

        if not field:
            base.status = CheckStatus.UNKNOWN
            return base

        compliant     = [
            item for item in collection
            if self._get_nested(item, field) == value
        ]
        total         = len(collection)
        pct           = (len(compliant) / total * 100) if total else 0
        base.actual   = f"{pct:.1f}% ({len(compliant)}/{total})"
        base.drift_score = pct / 100

        if pct >= min_pct:
            base.status = CheckStatus.PASS
        elif pct >= min_pct * 0.8:
            base.status = CheckStatus.PARTIAL
            base.delta  = (
                f"{pct:.1f}% meet this requirement. "
                f"Target: {min_pct}%. "
                f"Gap: {total - len(compliant)} objects"
            )
        else:
            base.status         = CheckStatus.FAIL
            base.affected_count = total - len(compliant)
            base.delta          = (
                f"Only {pct:.1f}% meet this requirement. "
                f"Target: {min_pct}%. "
                f"{total - len(compliant)} objects are non-compliant."
            )

        return base

    def _check_staleness(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> CheckResult:
        """Check for objects that haven't been updated recently."""
        base       = self._base_result(control)
        collection = self._get_collection(control, state)

        if not collection:
            base.status = CheckStatus.UNKNOWN
            return base

        condition      = control.expected or {}
        date_field     = condition.get("field", "lastSyncDateTime")
        threshold_days = condition.get("threshold_days", 30)
        cutoff         = datetime.now(tz=timezone.utc) - timedelta(
            days=threshold_days
        )

        stale = []
        for item in collection:
            date_str = self._get_nested(item, date_field)
            if not date_str:
                stale.append(item)
                continue
            try:
                dt = datetime.fromisoformat(
                    date_str.replace("Z", "+00:00")
                )
                if dt < cutoff:
                    stale.append(item)
            except Exception:
                pass

        base.affected_count = len(stale)
        base.actual         = (
            f"{len(stale)} of {len(collection)} objects stale"
        )

        if not stale:
            base.status      = CheckStatus.PASS
            base.drift_score = 1.0
        else:
            ratio            = len(stale) / len(collection)
            base.status      = CheckStatus.FAIL
            base.drift_score = 1 - ratio
            base.delta       = (
                f"{len(stale)} objects not updated in "
                f"{threshold_days}+ days"
            )
            base.affected_objects = [
                item.get(
                    "deviceName",
                    item.get("displayName", str(item.get("id", "")))
                )
                for item in stale[:20]
            ]

        return base

    def _check_unknown(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> CheckResult:
        base        = self._base_result(control)
        base.status = CheckStatus.UNKNOWN
        base.delta  = f"Unknown check type: {control.check_type}"
        return base

    # ── Helpers ──────────────────────────────────────────────────────────

    def _base_result(self, control: BaselineControl) -> CheckResult:
        return CheckResult(
            control_id=control.control_id,
            framework=control.framework,
            title=control.title,
            severity=control.severity,
            effort=control.effort,
            status=CheckStatus.UNKNOWN,
            expected=control.expected,
            blast_radius=control.blast_radius,
            community_ref=control.community_ref,
            checked_at=datetime.now(tz=timezone.utc),
        )

    def _get_collection(
        self,
        control: BaselineControl,
        state: TenantState,
    ) -> Any:
        """Map a Graph API endpoint to the relevant tenant state list."""
        ep = control.graph_endpoint
        mapping = {
            "/identity/conditionalAccess/policies": state.ca_policies,
            "/users":                               state.users,
            "/guests":                              state.guests,
            "/admins":                              state.admins,
            "/reports/authenticationMethods":       state.mfa_registration,
            "/deviceManagement/managedDevices":     state.managed_devices,
            "/deviceManagement/deviceCompliance":   state.compliance_policies,
            "/deviceManagement/deviceConfigurations":state.config_profiles,
            "/security/secureScores":               [state.secure_score],
            "/security/alerts_v2":                  state.alerts,
            "/domains":                             state.domains,
            "/directoryRoles":                      state.roles,
            "/servicePrincipals":                   state.service_principals,
        }
        for key, collection in mapping.items():
            if key in ep:
                return collection
        return None

    def _filter_objects(
        self,
        collection: list[dict],
        conditions: dict,
    ) -> list[dict]:
        """Filter a collection by matching conditions."""
        results = []
        for item in collection:
            if all(
                self._get_nested(item, k) == v
                for k, v in conditions.items()
                if not k.startswith("_")
            ):
                results.append(item)
        return results

    def _get_nested(self, obj: dict, path: str) -> Any:
        """Get a nested value from a dict using dot notation."""
        if not path:
            return None
        parts  = path.split(".")
        result = obj
        for part in parts:
            if isinstance(result, dict):
                result = result.get(part)
            else:
                return None
        return result
