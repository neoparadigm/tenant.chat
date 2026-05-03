# Tenant.Chat

<img width="769" height="295" alt="image" src="https://github.com/user-attachments/assets/1cc0def1-2646-46c3-b952-3f6d190836d4" />



## Install

# tenant.chat

> Local-first conversational AI agent for Microsoft tenant intelligence. 
> Assess your tenant. Understand what drifted. Know what breaks before you fix it. Comply with yearly audit cycles and STOP manually inspecting your tenant.
> Runs on your hardware. Nothing leaves your machine.

---

## What it does

- Assesses your M365 tenant against **118 controls** across 8 security frameworks
- Detects configuration drift — not just pass/fail, exact deltas with affected object counts
- Models **blast radius** before any change — your specific named objects, not generic warnings
- Segments users into actionable risk clusters via K-means
- Maps findings directly to the **CISA March 2026 advisory** (Stryker/Handala breach)
- Explains every finding in plain English with AI-generated remediation sequences
- Generates board-ready PDF reports — Executive, Technical, and Audit formats
- Remembers decisions and posture history across sessions

## What makes it different

Most community tools wrap PowerShell and produce an HTML report.  
No conversation. No blast radius. No memory. No AI analysis.

tenant.chat is a local AI agent that understands your specific tenant — 1,200 service principals with stale secrets, 6 permanent Global Admins when 2 are allowed, no CA policies covering Intune admin portal. Real findings. Tenant-specific context.

![tenant.chat screenshot](https://github.com/user-attachments/assets/418251f8-6353-4a73-870a-a4013feaf5af)

---

## Install

**From PyPI:**
```bash
pip install tenantchat
```

**From GitHub (latest):**
```bash
pip install git+https://github.com/neoparadigm/tenant.chat.git
```

**From source:**
```bash
git clone https://github.com/neoparadigm/tenant.chat.git
cd tenant.chat
pip install -e .
```

---

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com) with Gemma 4:
```bash
  ollama pull gemma4
```
- Microsoft Entra app registration (read-only delegated permissions — see below)

---

## Entra app setup

1. Go to [portal.azure.com](https://portal.azure.com) → **Entra ID** → **App registrations** → **New registration**
2. Name: `tenant.chat` — Supported account types: **Single tenant**
3. Redirect URI: **Public client/native** → `http://localhost`
4. **API permissions** → Add → Microsoft Graph → Delegated:

| Permission | Purpose |
|---|---|
| `User.Read.All` | User enumeration and guest access |
| `UserAuthenticationMethod.Read.All` | MFA registration and phishing-resistant MFA |
| `Policy.Read.All` | Conditional Access policies |
| `DeviceManagementManagedDevices.Read.All` | Intune managed device compliance |
| `DeviceManagementConfiguration.Read.All` | Intune configuration profiles |
| `DeviceManagementRBAC.Read.All` | Intune RBAC and scope tags |
| `SecurityEvents.Read.All` | Security alerts and risky users |
| `AuditLog.Read.All` | Sign-in logs and audit events |
| `Reports.Read.All` | Authentication method usage reports |
| `Directory.Read.All` | Roles, groups, service principals |
| `RoleManagement.Read.Directory` | PIM role assignments |
| `Domain.Read.All` | Domain verification and password policy |

5. **Grant admin consent**
6. **Authentication** → Advanced settings → **Allow public client flows** → Yes

---

## Quick start

```bash
# Set your Entra app credentials
export TENANTCHAT_CLIENT_ID=your-app-client-id
export TENANTCHAT_TENANT_ID=your-tenant-id

# Or create a .env file
echo "TENANTCHAT_CLIENT_ID=your-app-client-id" > .env
echo "TENANTCHAT_TENANT_ID=your-tenant-id" >> .env

# Authenticate
tenantchat auth login

# Launch the UI
tenantchat serve
# Open http://localhost:8001

# Or use the CLI directly
tenantchat assess
tenantchat assess --baseline intune
tenantchat report --type exec
```

---

tenantchat serve              Launch the web UI at http://localhost:8001
tenantchat auth login         Authenticate against your M365 tenant
tenantchat auth status        Check current authentication state
tenantchat assess             Run full assessment (all 118 controls)
tenantchat assess --baseline  Run specific framework only
tenantchat report --type exec     Generate executive PDF report
tenantchat report --type technical  Generate technical PDF report
tenantchat report --type audit      Generate audit/compliance PDF report

## Quick UI Commands
/assess , /report executive , /report technical , /report audit

## AI stack

| Component | Library | Purpose |
|---|---|---|
| Local inference | Ollama + Gemma 4 | Default, free, local |
| Embeddings | sentence-transformers | Semantic drift scoring |
| Vector store | ChromaDB | Local persistent storage |
| Agent flows | LangGraph | Stateful conversation |
| Memory | Mem0 | Cross-session context |
| Clustering | scikit-learn K-means | User risk segmentation |
| PII scrubbing | Microsoft Presidio | Privacy before LLM |
| Reports | WeasyPrint + Jinja2 | PDF generation |
| Cloud opt-in | Claude API | Enhanced reasoning |


## Baselines included (118 controls)

| Framework | Controls | Source |
|---|---|---|
| Microsoft Entra Identity Security Baseline | 27 | Microsoft + CISA advisory |
| Microsoft Intune Security Baseline | 23 | Microsoft + CISA advisory |
| CIS Microsoft 365 Foundations v3.1 | 15 | CIS Benchmarks |
| Microsoft Exchange and Purview Security Baseline | 17 | Microsoft |
| NIST 800-53 M365 Mapping | 14 | NIST Rev 5 |
| Microsoft Azure Security Baseline | 9 | Microsoft |
| Microsoft Baseline Security Mode | 8 | Microsoft |
| Microsoft Zero Trust RaMP | 5 | Microsoft |

**CISA March 2026 advisory (Stryker/Handala breach) is directly mapped across Intune and Entra baselines.**  
Specific controls: Multi Admin Approval for device wipe, phishing-resistant MFA for admins, PIM for Intune roles, least privilege Intune RBAC.

---

## AI stack

| Component | Library | Purpose |
|---|---|---|
| Local inference | Ollama + Gemma 4 | Findings analysis, blast radius, fix sequences |
| Embeddings | sentence-transformers | Semantic CA policy coverage scoring |
| Vector store | ChromaDB | Local persistent baseline storage |
| Agent flows | LangGraph | Stateful conversation engine |
| Memory | Mem0 | Cross-session posture history |
| Clustering | scikit-learn K-means | User risk segmentation |
| PII scrubbing | Microsoft Presidio | Privacy layer before any LLM call |
| Reports | WeasyPrint + Jinja2 | PDF generation (exec/technical/audit) |

---

## Report types

**Executive** — Board-ready. Posture score, top 5 critical findings, quick wins table, AI narrative. No technical detail.

**Technical** — Full assessment. All charts, all findings, AI analysis per finding with blast radius and fix sequences.

**Audit** — Compliance evidence. All 118 controls grouped by framework with pass/fail/unknown status. No AI analysis.

---

## Privacy

All tenant data stays on your machine.  
Microsoft Presidio scrubs UPNs, device names, and IP addresses before any LLM call.  
Policy names and group names are preserved — they are configuration, not personal data.

- **Ollama mode** — zero data transmission. Everything local.
- **Claude API mode** — anonymised context only, never raw tenant data.

No telemetry. No analytics. No callbacks.

---

## Contributing

Baseline YAML files in `baselines/` are community-maintained.  
When Microsoft publishes a new baseline version or a new CISA advisory drops — submit a PR.

See `baselines/README.md` for the control schema and contribution guide.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built by [Subh](https://github.com/neoparadigm) — neoparadigm open-source Modern Workplace intelligence platform.*
EOF

## Privacy

All tenant data stays on your machine. Microsoft Presidio scrubs UPNs, 
device names, and IP addresses before any LLM call. Policy names and 
group names are preserved — they are configuration, not personal data.

Ollama mode: zero data transmission.
Claude API mode: anonymised context only, never raw tenant data.

## Contributing

Baseline YAML files in `baselines/` are community-maintained.
When Microsoft publishes a new baseline version — submit a PR.

## License

MIT — github.com/neoparadigm/tenantchat

## Author


built by Subh - neoparadigm open-source Modern Workplace intelligence platform.
