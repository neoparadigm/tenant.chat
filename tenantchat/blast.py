"""Blast radius analysis — cross-references proposed changes against tenant state."""

from __future__ import annotations

from tenantchat.models import BlastRadiusResult, TenantState


# Community-sourced blast radius knowledge base
# Each entry maps a change type to known breakages
# Cross-referenced against actual tenant state at runtime

BLAST_KNOWLEDGE: dict[str, dict] = {
    "block_legacy_auth": {
        "keywords": [
            "legacy auth", "basic auth", "block legacy",
            "exchangeactivesync", "other clients", "imap", "pop",
            "smtp auth", "ews",
        ],
        "generic_breakages": [
            "Exchange ActiveSync devices using basic authentication",
            "IMAP and POP email clients",
            "Applications using basic auth to Exchange Online",
            "Printers and scanners using SMTP AUTH scan-to-email",
            "Older Outlook versions prior to 2013",
            "EWS-based applications not yet migrated to Graph API",
        ],
        "tenant_checks": [
            {
                "description": "Shared mailboxes with IMAP enabled",
                "collection":  "managed_devices",
                "hint":        "Check shared mailboxes for IMAP/POP access",
            },
            {
                "description": "Service principals using legacy auth",
                "collection":  "service_principals",
                "hint":        "Review app registrations for EWS/basic auth",
            },
        ],
        "fix_sequence": [
            "1. Identify all IMAP/POP clients using audit logs",
            "2. Migrate printers to modern auth or dedicated SMTP relay",
            "3. Migrate applications from EWS/basic auth to Graph API",
            "4. Create CA policy in report-only mode first",
            "5. Monitor sign-in logs for legacy auth attempts",
            "6. Enable the policy after 2-week observation period",
        ],
        "risk_level": "high",
    },
    "enforce_mfa": {
        "keywords": [
            "enforce mfa", "require mfa", "mfa policy",
            "authentication strength", "multifactor",
        ],
        "generic_breakages": [
            "Users without MFA registered will be blocked immediately",
            "Service accounts used by applications cannot complete MFA",
            "Shared mailboxes with direct sign-in will break",
            "Break glass emergency access accounts must be excluded",
            "Guest users may be blocked if included in policy scope",
            "Automation accounts using username/password auth will fail",
        ],
        "tenant_checks": [
            {
                "description": "Users without MFA registered",
                "collection":  "mfa_registration",
                "hint":        "isMfaRegistered eq false",
            },
            {
                "description": "Service accounts in scope",
                "collection":  "service_principals",
                "hint":        "Service principals that sign in interactively",
            },
        ],
        "fix_sequence": [
            "1. Run MFA registration campaign for unregistered users",
            "2. Identify and exclude service accounts from MFA policy",
            "3. Configure break glass accounts with exclusion group",
            "4. Set policy to report-only for 2 weeks",
            "5. Review sign-in logs for MFA failures",
            "6. Enable policy enforcement after registration campaign",
        ],
        "risk_level": "high",
    },
    "require_compliant_device": {
        "keywords": [
            "compliant device", "require compliant", "device compliance",
            "intune enrolled", "managed device",
        ],
        "generic_breakages": [
            "Personal and BYOD devices will immediately lose access",
            "Unmanaged devices used for admin tasks will be blocked",
            "Guest users on unmanaged devices will lose access",
            "Mobile devices not enrolled in Intune will be blocked",
            "Devices in pending compliance state will be blocked",
        ],
        "tenant_checks": [
            {
                "description": "Non-compliant managed devices",
                "collection":  "managed_devices",
                "hint":        "complianceState neq compliant",
            },
        ],
        "fix_sequence": [
            "1. Identify all non-compliant devices and remediate",
            "2. Enrol all target devices in Intune before enabling",
            "3. Configure compliance policies with grace period",
            "4. Exclude break glass and admin workstations initially",
            "5. Enable in report-only mode first",
            "6. Enable enforcement after device enrolment verified",
        ],
        "risk_level": "high",
    },
    "enable_pim": {
        "keywords": [
            "pim", "privileged identity", "just in time",
            "eligible assignment", "activate role",
        ],
        "generic_breakages": [
            "Admins will need to activate roles before performing tasks",
            "Automated scripts using permanent admin accounts will fail",
            "Helpdesk workflows assuming permanent admin access need updating",
            "Break glass accounts must remain permanent Global Admin",
            "Azure DevOps pipelines using admin service principals affected",
        ],
        "tenant_checks": [
            {
                "description": "Permanent Global Admins to convert",
                "collection":  "admins",
                "hint":        "All current Global Admin assignments",
            },
        ],
        "fix_sequence": [
            "1. Identify all automation using permanent admin accounts",
            "2. Create dedicated service principals for automation",
            "3. Configure PIM with appropriate activation duration",
            "4. Train admins on PIM activation workflow",
            "5. Keep 2 break glass accounts as permanent Global Admin",
            "6. Convert remaining admins to eligible PIM assignments",
        ],
        "risk_level": "medium",
    },
    "block_external_forwarding": {
        "keywords": [
            "external forwarding", "auto forward", "smtp forwarding",
            "forwarding rules", "redirect external",
        ],
        "generic_breakages": [
            "Legitimate auto-forward rules to personal email will break",
            "Business mail flow rules forwarding to partners will break",
            "Shared mailbox delegation forwarding may be affected",
        ],
        "tenant_checks": [],
        "fix_sequence": [
            "1. Audit all existing forwarding rules in Exchange Admin",
            "2. Identify legitimate business forwarding needs",
            "3. Create approved exceptions for legitimate cases",
            "4. Enable outbound spam policy block",
            "5. Monitor mail flow logs after enabling",
        ],
        "risk_level": "medium",
    },
}


class BlastAnalyzer:
    """
    Analyses blast radius of a proposed configuration change.

    Cross-references community knowledge against actual tenant state
    to give tenant-specific impact rather than generic warnings.
    """

    def analyze(
        self,
        change_description: str,
        state: TenantState,
    ) -> BlastRadiusResult:
        """Analyse blast radius for a proposed change."""
        change_lower = change_description.lower()

        # Match change to knowledge base entry
        matched_key  = None
        matched_data = None

        for key, data in BLAST_KNOWLEDGE.items():
            if any(kw in change_lower for kw in data["keywords"]):
                matched_key  = key
                matched_data = data
                break

        if not matched_data:
            return BlastRadiusResult(
                change_description=change_description,
                affected_objects=[],
                risk_level="unknown",
                sequence=[
                    "No specific blast radius data available for this change.",
                    "Review Microsoft documentation before applying.",
                    "Consider enabling in report-only mode first.",
                ],
                fix_first=[],
            )

        # Cross-reference against actual tenant state
        affected_objects = []

        # Add generic breakages
        for breakage in matched_data["generic_breakages"]:
            affected_objects.append({
                "type":        "generic",
                "description": breakage,
                "count":       None,
                "objects":     [],
            })

        # Tenant-specific checks
        for check in matched_data.get("tenant_checks", []):
            collection_name = check["collection"]
            collection = getattr(state, collection_name, [])

            if collection_name == "mfa_registration":
                # Count users without MFA
                unregistered = [
                    u for u in collection
                    if not u.get("isMfaRegistered", True)
                ]
                if unregistered:
                    affected_objects.append({
                        "type":        "tenant_specific",
                        "description": check["description"],
                        "count":       len(unregistered),
                        "objects":     [],  # scrubbed elsewhere
                        "hint":        check["hint"],
                    })

            elif collection_name == "managed_devices":
                non_compliant = [
                    d for d in collection
                    if d.get("complianceState") != "compliant"
                ]
                if non_compliant:
                    affected_objects.append({
                        "type":        "tenant_specific",
                        "description": check["description"],
                        "count":       len(non_compliant),
                        "objects":     [],
                        "hint":        check["hint"],
                    })

            elif collection_name == "admins":
                if collection:
                    affected_objects.append({
                        "type":        "tenant_specific",
                        "description": check["description"],
                        "count":       len(collection),
                        "objects":     [],
                        "hint":        check["hint"],
                    })

            elif collection_name == "service_principals":
                if collection:
                    affected_objects.append({
                        "type":        "tenant_specific",
                        "description": check["description"],
                        "count":       len(collection),
                        "objects":     [],
                        "hint":        check["hint"],
                    })

        # Determine overall risk level
        tenant_specific = [
            o for o in affected_objects
            if o["type"] == "tenant_specific" and o.get("count", 0)
        ]
        risk_level = (
            "critical" if len(tenant_specific) >= 3
            else "high"   if len(tenant_specific) >= 1
            else matched_data["risk_level"]
        )

        return BlastRadiusResult(
            change_description=change_description,
            affected_objects=affected_objects,
            risk_level=risk_level,
            sequence=matched_data["fix_sequence"],
            fix_first=[
                o["description"]
                for o in affected_objects
                if o["type"] == "tenant_specific"
                and o.get("count", 0) > 0
            ],
        )

    def format_for_display(self, result: BlastRadiusResult) -> str:
        """Format blast radius result as plain text for CLI/LLM context."""
        lines = [
            f"BLAST RADIUS — {result.change_description}",
            f"Risk level: {result.risk_level.upper()}",
            "",
        ]

        tenant_specific = [
            o for o in result.affected_objects
            if o["type"] == "tenant_specific"
        ]
        generic = [
            o for o in result.affected_objects
            if o["type"] == "generic"
        ]

        if tenant_specific:
            lines.append("YOUR TENANT — specific impact:")
            for obj in tenant_specific:
                count = f" ({obj['count']} objects)" if obj.get("count") else ""
                lines.append(f"  ⚠ {obj['description']}{count}")
            lines.append("")

        if generic:
            lines.append("KNOWN BREAKAGES from community experience:")
            for obj in generic:
                lines.append(f"  • {obj['description']}")
            lines.append("")

        if result.fix_first:
            lines.append("FIX THESE FIRST:")
            for item in result.fix_first:
                lines.append(f"  → {item}")
            lines.append("")

        lines.append("RECOMMENDED SEQUENCE:")
        for step in result.sequence:
            lines.append(f"  {step}")

        return "\n".join(lines)
