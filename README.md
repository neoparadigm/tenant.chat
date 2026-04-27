# Tenant.Chat

<img width="576" height="266" alt="image" src="https://github.com/user-attachments/assets/215db755-f563-4aa6-b434-cf78d65cbf66" />


> Local-first conversational AI agent for Microsoft 365 security assessment.

Connect to your tenant. Assess against every major security baseline. 
Understand what drifted, why it matters, and what breaks before you fix it.
All on your own hardware. Nothing leaves your machine.

---

## What it does

- Assesses your M365 tenant against Microsoft BSM, CIS, Zero Trust RaMP
- Detects configuration drift — not just pass/fail, exact deltas
- Models blast radius before any change — your specific affected objects
- Segments users into actionable risk clusters via K-means
- Explains every finding in plain English with community context
- Generates board-ready PDF reports
- Remembers decisions across sessions

## What makes it different

Most community tools wrap PowerShell plus an HTML report without much explanation.
No conversation. No blast radius. No memory.

tenant.chat is a local AI agent that understands your specific tenant.


<img width="1872" height="1052" alt="image" src="https://github.com/user-attachments/assets/418251f8-6353-4a73-870a-a4013feaf5af" />


## Install

```bash
pip install tenantchat
```

## Quick start

```bash
# Set your Entra app credentials
export TENANTCHAT_CLIENT_ID=your-app-client-id
export TENANTCHAT_TENANT_ID=your-tenant-id

# Authenticate
tenantchat auth login

# Run assessment
tenantchat assess

# Interactive mode
tenantchat
```

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com) with Gemma 4: `ollama pull gemma4`
- Microsoft Entra app registration (read-only delegated permissions)

## Entra app setup

1. Go to portal.azure.com → Entra ID → App registrations → New registration
2. Name: `tenant.chat` — Supported account types: Single tenant
3. Redirect URI: Public client/native → `http://localhost`
4. API permissions → Add → Microsoft Graph → Delegated:
   - User.Read.All
   - UserAuthenticationMethod.Read.All
   - Policy.Read.All
   - DeviceManagementManagedDevices.Read.All
   - DeviceManagementConfiguration.Read.All
   - SecurityEvents.Read.All
   - AuditLog.Read.All
   - Reports.Read.All
   - Directory.Read.All
5. Grant admin consent
6. Authentication → Advanced settings → Allow public client flows → Yes

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

## Baselines included

- Microsoft Baseline Security Mode
- Microsoft Intune Security Baselines
- CIS Microsoft 365 Foundations v3.1
- Microsoft Zero Trust RaMP
- NIST 800-53 M365 mapping (coming)

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


built by Subh - neoparadigm open-source Modern Workplace intelligence platform.# tenant.chat

Local-first conversational AI agent for M365 tenant security assessment.

## Install
pip install tenantchat

## Quick start
tenantchat
