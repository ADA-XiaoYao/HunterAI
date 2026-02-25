# HunterAI 🎯

> **AlfaNet Organization** — Fully original, autonomous AI-powered penetration testing platform.
> Author: xiaoyao | Version: 1.0.0 | 2026

⚠️ **For authorized penetration testing only. Only use against systems you own or have explicit written permission to test.**

---

## Philosophy

> **"AI as the decision brain. Event-driven dynamic attack. Vulnerability chains auto-escalate."**

HunterAI uses an **event-driven multi-agent architecture**:
- Every module discovery is immediately broadcast via the internal EventBus
- The Orchestrator Agent re-evaluates priorities in real time and dynamically schedules the next step
- Multiple low-severity findings are automatically chained into critical exploit paths
- Zero human intervention required — one command from recon to report

---

## Architecture

```
hunterai/
├── hunterai/
│   ├── core/
│   │   ├── engine.py          # Event-driven scheduling engine
│   │   ├── eventbus.py        # Async event bus
│   │   └── session.py         # Shared session state
│   ├── agents/
│   │   ├── orchestrator.py    # AI command center (real-time decision & scheduling)
│   │   └── attack_agent.py    # Attack planning agent
│   ├── modules/
│   │   ├── recon/             # Subdomain / port / fingerprint / OSINT
│   │   ├── vulnscan/          # Web vulnerability scanning
│   │   ├── apifuzz/           # REST / GraphQL / gRPC API testing
│   │   ├── auth/              # JWT / OAuth / session / IDOR
│   │   ├── exploit/           # Exploit chain builder
│   │   ├── postexploit/       # Post-exploitation & lateral movement
│   │   ├── cloud/             # AWS / GCP / Azure misconfiguration
│   │   └── report/            # Multilingual report generator
│   ├── llm/
│   │   └── router.py          # Multi-model LLM router
│   └── db/
│       └── store.py           # Persistent knowledge store
├── web/                       # React management dashboard
├── docker/
├── config/
└── tests/
```

---

## Quick Start

```bash
# Install
git clone https://github.com/alfanet/hunterai
cd hunterai
pip install -e .

# Configure
cp config/hunterai.example.yaml config/hunterai.yaml
# Edit: add LLM API keys

# Docker (recommended)
docker compose up -d

# CLI
hunterai scan --target https://example.com --mode full
hunterai scan --target https://example.com --mode quick
hunterai status

# Web UI
open http://localhost:3000
```

---

## Scan Profiles

| Profile | Modules | Est. Time |
|---|---|---|
| `quick` | recon + vulnscan | ~15 min |
| `standard` | recon + vulnscan + apifuzz + auth | ~1 hr |
| `full` | All modules | ~2–3 hr |
| `cloud` | recon + cloud | ~30 min |
| `api` | recon + apifuzz + auth | ~45 min |

---

## License
MIT — AlfaNet Organization. Internal use only.
