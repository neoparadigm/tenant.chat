"""Active M365 attack campaign data with MITRE ATT&CK mappings and graph schema.

Each campaign is modelled as a directed graph of attack steps (nodes) connected
by attacker transitions (edges).  Every node carries the tenant.chat control IDs
that, if passing, would block or detect that step.  The /api/attack-graph endpoint
overlays live assessment results so the UI can colour nodes by control status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

NodeType = Literal[
    "initial_access",
    "execution",
    "credential_access",
    "lateral_movement",
    "persistence",
    "exfiltration",
    "impact",
]


@dataclass
class CampaignNode:
    """A single attack step node in the campaign graph."""

    id:              str
    label:           str           # short label shown on graph node
    campaign_id:     str
    mitre_id:        str           # e.g. T1566.002
    mitre_name:      str           # human-readable technique name
    node_type:       NodeType
    description:     str           # full description for detail panel
    control_ids:     list[str] = field(default_factory=list)
    # tenant.chat agent that can remediate this gap (empty = no automated fix)
    suggested_agent: str = ""


@dataclass
class CampaignEdge:
    """Directed edge between two attack steps."""

    source: str
    target: str
    label:  str = ""   # short action label shown on edge


@dataclass
class Campaign:
    """An active M365 attack campaign."""

    id:           str
    name:         str
    description:  str
    actor:        str
    active_since: str   # YYYY-MM
    severity:     str   # critical / high / medium
    references:   list[str] = field(default_factory=list)


# ── Campaigns ─────────────────────────────────────────────────────────────────

CAMPAIGNS: list[Campaign] = [
    Campaign(
        id="storm-2372",
        name="Storm-2372",
        description=(
            "Nation-state group using device code phishing to steal OAuth tokens "
            "without triggering MFA.  Initiates the authentication flow from the "
            "attacker's device so the victim completes MFA for the attacker."
        ),
        actor="Storm-2372 (Microsoft threat intelligence)",
        active_since="2024-08",
        severity="critical",
        references=[
            "https://www.microsoft.com/en-us/security/blog/2025/02/13/"
            "storm-2372-conducts-device-code-phishing-campaign/",
        ],
    ),
    Campaign(
        id="aitm-tycoon2fa",
        name="AiTM / Tycoon2FA",
        description=(
            "Adversary-in-the-middle phishing kit proxying Microsoft login pages. "
            "Captures session cookies after MFA completes, bypassing TOTP/push MFA. "
            "Phishing-resistant MFA and CAE are the primary defences."
        ),
        actor="Multiple eCrime groups; Tycoon2FA Phishing-as-a-Service",
        active_since="2023-06",
        severity="critical",
        references=[
            "https://www.microsoft.com/en-us/security/blog/2023/06/08/"
            "detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/",
        ],
    ),
    Campaign(
        id="handala-stryker",
        name="Handala / Stryker Breach",
        description=(
            "Threat actor compromised a Global Administrator via AiTM phishing, "
            "created a backdoor GA account, then used Intune to wipe 80,000 managed "
            "devices.  Subject of CISA advisory March 2026."
        ),
        actor="Handala (Iran-nexus) — CISA advisory Mar 2026",
        active_since="2026-03",
        severity="critical",
        references=[
            "https://www.cisa.gov/news-events/alerts/2026/03/18/"
            "cisa-urges-endpoint-management-system-hardening-after-cyberattack-"
            "against-us-organization",
        ],
    ),
    Campaign(
        id="qr-phishing",
        name="QR Code Phishing",
        description=(
            "QR codes embedded in emails bypass link-scanning security tools. "
            "Users scan with personal devices that lack corporate email security, "
            "landing on credential-harvesting pages."
        ),
        actor="Multiple eCrime groups",
        active_since="2023-09",
        severity="high",
        references=[
            "https://www.microsoft.com/en-us/security/blog/2023/10/03/"
            "defending-new-vectors-threat-actors-attempt-to-use-qr-codes/",
        ],
    ),
    Campaign(
        id="sharepoint-bec",
        name="SharePoint BEC",
        description=(
            "Attackers send legitimate SharePoint notification emails with embedded "
            "phishing links.  High deliverability due to Microsoft-signed email. "
            "Used to steal credentials and conduct Business Email Compromise."
        ),
        actor="Multiple eCrime groups (BEC focus)",
        active_since="2023-11",
        severity="high",
        references=[
            "https://www.microsoft.com/en-us/security/blog/2023/11/13/"
            "sharepoint-phishing-targets-business-email-compromise/",
        ],
    ),
    Campaign(
        id="domain-spoofing",
        name="Domain Spoofing / Homoglyph",
        description=(
            "Attackers register lookalike domains using homoglyphs or typosquatting "
            "to send convincing phishing emails.  Weak DMARC enforcement allows "
            "these emails to reach user inboxes."
        ),
        actor="Multiple threat actors",
        active_since="2022-01",
        severity="high",
        references=[
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/"
            "anti-spoofing-protection",
        ],
    ),
]


# ── Nodes ─────────────────────────────────────────────────────────────────────

NODES: list[CampaignNode] = [

    # ── Storm-2372 ──────────────────────────────────────────────────────────

    CampaignNode(
        id="storm_phish",
        label="Phishing email\nwith device code",
        campaign_id="storm-2372",
        mitre_id="T1566.002",
        mitre_name="Spearphishing Link",
        node_type="initial_access",
        description=(
            "Attacker sends an email containing a Microsoft device code authentication "
            "URL (aka.ms/devicelogin).  The email uses legitimate Microsoft branding "
            "and asks the user to enter a device code to 'complete a security check'."
        ),
        control_ids=["ENTRA-MFA-01", "ENTRA-MFA-02"],
        suggested_agent="",
    ),
    CampaignNode(
        id="storm_device_code",
        label="Device code OAuth\nflow initiated",
        campaign_id="storm-2372",
        mitre_id="T1528",
        mitre_name="Steal Application Access Token",
        node_type="credential_access",
        description=(
            "Attacker initiates a device code OAuth flow using a legitimate Microsoft "
            "application client ID, generates a user code, and polls for the resulting "
            "token.  The flow is not blocked by standard MFA policies because the "
            "authentication happens on the victim's device at the attacker's request."
        ),
        control_ids=["ENTRA-DC-01"],
        suggested_agent="device-code-block",
    ),
    CampaignNode(
        id="storm_token_acquired",
        label="OAuth token acquired\nwithout attacker MFA",
        campaign_id="storm-2372",
        mitre_id="T1550.004",
        mitre_name="Use Alternate Authentication Material",
        node_type="credential_access",
        description=(
            "Victim completes MFA on their own device.  Attacker's polling request "
            "receives a full access + refresh token pair.  The token is valid for up "
            "to 90 days and is not bound to the attacker's device or IP address."
        ),
        control_ids=["ENTRA-DC-01", "ENTRA-CAE-01", "ENTRA-TOKEN-01"],
        suggested_agent="device-code-block",
    ),
    CampaignNode(
        id="storm_lateral",
        label="Lateral movement\nvia stolen tokens",
        campaign_id="storm-2372",
        mitre_id="T1078.004",
        mitre_name="Valid Accounts: Cloud Accounts",
        node_type="lateral_movement",
        description=(
            "Attacker uses the stolen OAuth token to access M365 services as the "
            "victim.  Access persists until the token expires or is explicitly revoked. "
            "CAE is the fastest revocation mechanism once a token has been stolen."
        ),
        control_ids=["ENTRA-CAE-01", "ENTRA-PRIV-01", "ENTRA-PRIV-02"],
        suggested_agent="aitm-hardening",
    ),
    CampaignNode(
        id="storm_persistence",
        label="Persistence via\nrefresh token",
        campaign_id="storm-2372",
        mitre_id="T1098",
        mitre_name="Account Manipulation",
        node_type="persistence",
        description=(
            "Attacker uses the long-lived refresh token to continuously obtain new "
            "access tokens without further user interaction.  Persistence can last "
            "90 days without token lifetime restrictions."
        ),
        control_ids=["ENTRA-TOKEN-01", "ENTRA-TOKEN-02", "ENTRA-IDP-03"],
        suggested_agent="aitm-hardening",
    ),

    # ── AiTM / Tycoon2FA ────────────────────────────────────────────────────

    CampaignNode(
        id="aitm_proxy",
        label="Reverse-proxy\nphishing page",
        campaign_id="aitm-tycoon2fa",
        mitre_id="T1566.002",
        mitre_name="Spearphishing Link",
        node_type="initial_access",
        description=(
            "Attacker deploys a Tycoon2FA or Evilginx reverse-proxy.  The victim "
            "receives a link to a convincing Microsoft login page that transparently "
            "proxies the real authentication flow, capturing all credentials and MFA "
            "responses in real time."
        ),
        control_ids=["ENTRA-MFA-02"],
        suggested_agent="aitm-hardening",
    ),
    CampaignNode(
        id="aitm_session_capture",
        label="Session cookie\ncaptured post-MFA",
        campaign_id="aitm-tycoon2fa",
        mitre_id="T1539",
        mitre_name="Steal Web Session Cookie",
        node_type="credential_access",
        description=(
            "After the victim completes genuine MFA through the proxy, the resulting "
            "authenticated session cookie is captured by the attacker's server. "
            "The cookie carries the full authenticated session."
        ),
        control_ids=["ENTRA-CAE-01", "ENTRA-TOKEN-02"],
        suggested_agent="aitm-hardening",
    ),
    CampaignNode(
        id="aitm_mfa_bypass",
        label="MFA bypassed via\nstolen session",
        campaign_id="aitm-tycoon2fa",
        mitre_id="T1550.004",
        mitre_name="Use Alternate Authentication Material",
        node_type="credential_access",
        description=(
            "Attacker imports the stolen session cookie into their browser and gains "
            "full authenticated access without passing MFA.  Phishing-resistant MFA "
            "(FIDO2/WHfB) is hardware-bound and cannot be proxied."
        ),
        control_ids=["ENTRA-MFA-02", "ENTRA-CA-06"],
        suggested_agent="aitm-hardening",
    ),
    CampaignNode(
        id="aitm_bec",
        label="Mailbox accessed\nfor BEC intelligence",
        campaign_id="aitm-tycoon2fa",
        mitre_id="T1114.002",
        mitre_name="Email Collection: Remote Email Collection",
        node_type="exfiltration",
        description=(
            "Attacker reads victim emails to understand active wire transfers, "
            "supplier relationships, and executive communication patterns.  This "
            "intelligence is used to craft convincing BEC messages."
        ),
        control_ids=["ENTRA-CA-01", "ENTRA-CA-02"],
        suggested_agent="",
    ),
    CampaignNode(
        id="aitm_inbox_rule",
        label="Inbox rule for\npersistent access",
        campaign_id="aitm-tycoon2fa",
        mitre_id="T1137.005",
        mitre_name="Office Application Startup: Outlook Rules",
        node_type="persistence",
        description=(
            "Attacker creates a hidden inbox rule to forward all email to an external "
            "address, or to delete security alerts before the victim sees them.  The "
            "rule survives password resets if not explicitly audited and removed."
        ),
        control_ids=["ENTRA-MAIL-01", "ENTRA-MAIL-02"],
        suggested_agent="inbox-rule-audit",
    ),

    # ── Handala / Stryker ────────────────────────────────────────────────────

    CampaignNode(
        id="stryker_admin_phish",
        label="Global Admin phished\nvia AiTM proxy",
        campaign_id="handala-stryker",
        mitre_id="T1566.002",
        mitre_name="Spearphishing Link",
        node_type="initial_access",
        description=(
            "A Global Administrator account was targeted with AiTM phishing. "
            "The admin completed MFA normally; the session cookie was captured. "
            "Phishing-resistant MFA (FIDO2) would have blocked proxy interception."
        ),
        control_ids=["ENTRA-MFA-02", "ENTRA-CA-06"],
        suggested_agent="stryker-defense",
    ),
    CampaignNode(
        id="stryker_ga_compromise",
        label="Global Admin session\ncompromised",
        campaign_id="handala-stryker",
        mitre_id="T1078.004",
        mitre_name="Valid Accounts: Cloud Accounts",
        node_type="lateral_movement",
        description=(
            "Attacker used the stolen GA session cookie to access Entra admin center. "
            "GA role provides unrestricted access to all M365 services, user accounts, "
            "and device management.  PIM limits the blast radius of a compromised account."
        ),
        control_ids=["ENTRA-PRIV-01", "ENTRA-PRIV-02", "ENTRA-CAE-01"],
        suggested_agent="stryker-defense",
    ),
    CampaignNode(
        id="stryker_new_ga",
        label="Backdoor GA account\ncreated",
        campaign_id="handala-stryker",
        mitre_id="T1136.001",
        mitre_name="Create Account: Local Account",
        node_type="persistence",
        description=(
            "Attacker created a new Global Administrator account to ensure persistent "
            "access even if the original compromised account was reset. "
            "An immediate alert on new GA account creation would have detected this."
        ),
        control_ids=["ENTRA-IDP-03", "ENTRA-PRIV-06"],
        suggested_agent="stryker-defense",
    ),
    CampaignNode(
        id="stryker_intune_wipe",
        label="Intune mass device\nwipe initiated",
        campaign_id="handala-stryker",
        mitre_id="T1485",
        mitre_name="Data Destruction",
        node_type="impact",
        description=(
            "Attacker used GA access to Microsoft Intune to initiate wipe commands on "
            "all managed devices.  Multi-admin approval for destructive Intune actions "
            "would have required a second admin to confirm before execution."
        ),
        control_ids=["ENTRA-PRIV-03"],
        suggested_agent="break-glass-setup",
    ),
    CampaignNode(
        id="stryker_destruction",
        label="80,000 devices wiped\nmass destruction",
        campaign_id="handala-stryker",
        mitre_id="T1485",
        mitre_name="Data Destruction",
        node_type="impact",
        description=(
            "Organisation-wide device wipe caused severe operational disruption. "
            "Recovery required re-imaging all managed devices.  This is the final "
            "impact stage of the Stryker attack chain described in the CISA advisory."
        ),
        control_ids=[],
        suggested_agent="",
    ),

    # ── QR Phishing ──────────────────────────────────────────────────────────

    CampaignNode(
        id="qr_delivery",
        label="QR code in email\nbypasses link scanner",
        campaign_id="qr-phishing",
        mitre_id="T1566",
        mitre_name="Phishing",
        node_type="initial_access",
        description=(
            "Email contains a QR code image instead of a hyperlink.  Email security "
            "tools that scan URLs miss the encoded link.  Victim scans with a personal "
            "mobile device lacking corporate email security controls."
        ),
        control_ids=["ENTRA-MFA-01"],
        suggested_agent="",
    ),
    CampaignNode(
        id="qr_cred_harvest",
        label="Credentials harvested\non fake login page",
        campaign_id="qr-phishing",
        mitre_id="T1556",
        mitre_name="Modify Authentication Process",
        node_type="credential_access",
        description=(
            "QR code leads to a convincing Microsoft login page that captures username, "
            "password, and potentially MFA codes.  Phishing-resistant MFA prevents "
            "credential capture because it is hardware-bound to the legitimate domain."
        ),
        control_ids=["ENTRA-MFA-02"],
        suggested_agent="aitm-hardening",
    ),
    CampaignNode(
        id="qr_takeover",
        label="Account takeover\nwith stolen creds",
        campaign_id="qr-phishing",
        mitre_id="T1078.004",
        mitre_name="Valid Accounts: Cloud Accounts",
        node_type="lateral_movement",
        description=(
            "Attacker uses captured credentials to sign in from an anomalous location. "
            "Risk-based Conditional Access (requires Entra ID P2) would detect the "
            "anomalous sign-in and block or require step-up authentication."
        ),
        control_ids=["ENTRA-CA-01", "ENTRA-CA-02"],
        suggested_agent="",
    ),
    CampaignNode(
        id="qr_bec",
        label="Mailbox accessed\nfor BEC / fraud",
        campaign_id="qr-phishing",
        mitre_id="T1114.002",
        mitre_name="Email Collection: Remote Email Collection",
        node_type="exfiltration",
        description=(
            "Attacker reads victim emails to gather BEC intelligence.  Inbox rules "
            "are created to forward emails and hide incoming security alerts from the "
            "victim, enabling extended dwell time."
        ),
        control_ids=["ENTRA-MAIL-01", "ENTRA-MAIL-02"],
        suggested_agent="inbox-rule-audit",
    ),

    # ── SharePoint BEC ───────────────────────────────────────────────────────

    CampaignNode(
        id="sp_lure",
        label="SharePoint notification\ncontains phish link",
        campaign_id="sharepoint-bec",
        mitre_id="T1566.002",
        mitre_name="Spearphishing Link",
        node_type="initial_access",
        description=(
            "Attacker shares a SharePoint document with the victim.  The resulting "
            "Microsoft-signed notification email from sharepoint.com bypasses many "
            "email security solutions.  The embedded link leads to a credential harvester."
        ),
        control_ids=["ENTRA-MFA-01"],
        suggested_agent="",
    ),
    CampaignNode(
        id="sp_creds",
        label="Credentials captured\nvia fake M365 page",
        campaign_id="sharepoint-bec",
        mitre_id="T1539",
        mitre_name="Steal Web Session Cookie",
        node_type="credential_access",
        description=(
            "Victim clicks the SharePoint notification link and lands on an AiTM proxy "
            "or credential harvester.  Password and MFA codes are captured.  "
            "Phishing-resistant MFA is the primary control."
        ),
        control_ids=["ENTRA-MFA-02"],
        suggested_agent="aitm-hardening",
    ),
    CampaignNode(
        id="sp_access",
        label="SharePoint and email\naccess gained",
        campaign_id="sharepoint-bec",
        mitre_id="T1213.002",
        mitre_name="Data from Information Repositories: SharePoint",
        node_type="exfiltration",
        description=(
            "Attacker accesses SharePoint to read sensitive documents, contracts, and "
            "financial data used to craft BEC attacks.  A compliant-device CA policy "
            "would block access from the unmanaged attacker device."
        ),
        control_ids=["ENTRA-CA-03", "ENTRA-APP-01"],
        suggested_agent="",
    ),
    CampaignNode(
        id="sp_bec",
        label="BEC invoice fraud\nexecuted",
        campaign_id="sharepoint-bec",
        mitre_id="T1114.002",
        mitre_name="Email Collection: Remote Email Collection",
        node_type="impact",
        description=(
            "Attacker uses email access and SharePoint intelligence to redirect wire "
            "transfers or intercept vendor payments.  Inbox rules hide vendor responses "
            "from the victim until the fraud is complete."
        ),
        control_ids=["ENTRA-MAIL-01", "ENTRA-MAIL-02"],
        suggested_agent="inbox-rule-audit",
    ),

    # ── Domain Spoofing ──────────────────────────────────────────────────────

    CampaignNode(
        id="dom_register",
        label="Lookalike domain\nregistered",
        campaign_id="domain-spoofing",
        mitre_id="T1036.005",
        mitre_name="Masquerading: Match Legitimate Name",
        node_type="initial_access",
        description=(
            "Attacker registers a domain visually similar to the target organisation "
            "using homoglyphs, typosquatting, or additional TLDs (e.g. contosо.com "
            "using a Cyrillic 'o').  Used to send convincing phishing emails."
        ),
        control_ids=["ENTRA-DOM-02"],
        suggested_agent="",
    ),
    CampaignNode(
        id="dom_email",
        label="Phishing from\nspoofed domain",
        campaign_id="domain-spoofing",
        mitre_id="T1566.002",
        mitre_name="Spearphishing Link",
        node_type="initial_access",
        description=(
            "Email sent from lookalike domain appears to come from the organisation. "
            "Weak DMARC / SPF / DKIM enforcement allows delivery.  Recipient sees the "
            "familiar company name in the email client sender field."
        ),
        control_ids=["ENTRA-MFA-01"],
        suggested_agent="",
    ),
    CampaignNode(
        id="dom_creds",
        label="Credentials captured\nfrom spoofed page",
        campaign_id="domain-spoofing",
        mitre_id="T1078.004",
        mitre_name="Valid Accounts: Cloud Accounts",
        node_type="credential_access",
        description=(
            "Victim believes the email is internal and clicks the malicious link. "
            "Credentials are captured on a fake Microsoft login page.  Risk-based CA "
            "can detect an anomalous sign-in from an unfamiliar location."
        ),
        control_ids=["ENTRA-MFA-02", "ENTRA-CA-01"],
        suggested_agent="aitm-hardening",
    ),
    CampaignNode(
        id="dom_compromise",
        label="Account compromised\nlegacy auth fallback",
        campaign_id="domain-spoofing",
        mitre_id="T1078.004",
        mitre_name="Valid Accounts: Cloud Accounts",
        node_type="impact",
        description=(
            "If the attacker cannot pass MFA, they attempt legacy authentication "
            "protocols (Basic, IMAP, POP, EWS) which bypass MFA entirely.  Blocking "
            "legacy authentication is the single highest-value identity control."
        ),
        control_ids=["ENTRA-LEGACY-01", "ENTRA-CA-01"],
        suggested_agent="",
    ),
]


# ── Edges ─────────────────────────────────────────────────────────────────────

EDGES: list[CampaignEdge] = [

    # Storm-2372
    CampaignEdge("storm_phish",         "storm_device_code",    "user clicks link"),
    CampaignEdge("storm_device_code",   "storm_token_acquired", "user enters code"),
    CampaignEdge("storm_token_acquired","storm_lateral",        "token used immediately"),
    CampaignEdge("storm_lateral",       "storm_persistence",    "refresh token rotated"),

    # AiTM / Tycoon2FA
    CampaignEdge("aitm_proxy",          "aitm_session_capture", "proxy captures session"),
    CampaignEdge("aitm_session_capture","aitm_mfa_bypass",      "cookie replayed"),
    CampaignEdge("aitm_mfa_bypass",     "aitm_bec",             "full mailbox access"),
    CampaignEdge("aitm_bec",            "aitm_inbox_rule",      "hide attacker activity"),

    # Handala / Stryker
    CampaignEdge("stryker_admin_phish",   "stryker_ga_compromise","GA session captured"),
    CampaignEdge("stryker_ga_compromise", "stryker_new_ga",       "backdoor created"),
    CampaignEdge("stryker_new_ga",        "stryker_intune_wipe",  "Intune GA access"),
    CampaignEdge("stryker_intune_wipe",   "stryker_destruction",  "mass wipe executed"),

    # QR Phishing
    CampaignEdge("qr_delivery",     "qr_cred_harvest", "user scans QR"),
    CampaignEdge("qr_cred_harvest", "qr_takeover",     "creds used to sign in"),
    CampaignEdge("qr_takeover",     "qr_bec",          "mailbox accessed"),

    # SharePoint BEC
    CampaignEdge("sp_lure",  "sp_creds",  "user clicks notification"),
    CampaignEdge("sp_creds", "sp_access", "authenticated as victim"),
    CampaignEdge("sp_access","sp_bec",    "BEC campaign launched"),

    # Domain Spoofing
    CampaignEdge("dom_register","dom_email",      "domain weaponised"),
    CampaignEdge("dom_email",   "dom_creds",      "victim clicks"),
    CampaignEdge("dom_creds",   "dom_compromise", "creds / session used"),
]


# ── Lookup helpers ────────────────────────────────────────────────────────────

def campaign_map() -> dict[str, Campaign]:
    return {c.id: c for c in CAMPAIGNS}


def nodes_for_campaign(campaign_id: str) -> list[CampaignNode]:
    if campaign_id == "all":
        return NODES
    return [n for n in NODES if n.campaign_id == campaign_id]


def edges_for_nodes(node_ids: set[str]) -> list[CampaignEdge]:
    return [e for e in EDGES if e.source in node_ids and e.target in node_ids]
