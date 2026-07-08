# Demo video script (3 minutes)

Use this script when recording a screen capture for README and portfolio.

## Setup

- Fly demo URL or `docker compose up -d --build`
- Terminal + browser for `/ui/approvals`
- Optional: `python examples/langgraph_gated_agent.py`

## Script

| Time | Scene | Narration |
|------|-------|-----------|
| 0:00–0:20 | Title card / README | "LLM agents call tools. Tools have real consequences. Agent Security Gate enforces policy before execution — not at the prompt layer." |
| 0:20–0:50 | `curl /health` + stack up | "One docker compose brings up OPA, Postgres, Redis, and the FastAPI gateway." |
| 0:50–1:30 | Four demo curls | "Doc exfiltration denied. SSRF blocked. Privilege escalation requires approval. Legitimate read allowed." |
| 1:30–2:00 | `/ui/approvals` approve flow | "Approvers resolve high-risk tools. Resume token binds the allow decision to execution." |
| 2:00–2:30 | `verify_audit.py` + LangGraph example | "Every decision is hash-chained. LangGraph tools call decide before side effects." |
| 2:30–3:00 | CI benchmark table | "CI proves attack blocking with threshold gates. Pilot-ready reference platform." |

## Publishing

- Upload unlisted to YouTube or attach to GitHub Release
- Embed link in [README.md](../README.md) hero section
- Add to [giselleevita profile README](https://github.com/giselleevita/giselleevita)
