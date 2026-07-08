# Demo video script (60–90 seconds)

Use the [README GIF](../assets/asg-demo.gif) as the core visual. Record voiceover + terminal, or screen capture of the GIF flow on a live demo.

## Setup

- Local: `docker compose up` → http://localhost:8000/demo
- Optional: browser on `/ui/approvals`

## Script

| Time | Visual | Narration |
|------|--------|-----------|
| 0–10s | Title / GIF first frame | "AI agents can call tools, access data, and trigger actions. That creates a new security boundary." |
| 10–25s | Architecture diagram or GIF typing | "Agent Security Gate sits between the agent and its tools. Every tool call is checked against policy before execution." |
| 25–50s | GIF: blocked request + audit JSON | "Here, the agent receives a prompt-injection attempt and tries to call a restricted tool. The gateway evaluates the request and blocks it." |
| 50–65s | GIF: audit trace line | "The decision is logged with the policy result, reason, and trace metadata — evidence for review." |
| 65–80s | GIF: allowed safe call | "Safe tool calls still pass through. The system enforces boundaries, it does not block everything." |
| 80–90s | README / repo link | "The goal: make AI agent actions enforceable, testable, and auditable." |

## Do not cover in the video

- OPA/Rego internals
- Full test suite walkthrough
- Every architecture component

Goal: make someone curious enough to inspect the repo in 15 minutes.

## Publishing

1. Upload unlisted to YouTube or attach to GitHub Release
2. Embed in [README.md](../README.md) **Try it** section
3. Add link on [portfolio](https://giselleevita.github.io/portfolio/)
4. Use [cross-post drafts](blog/cross-posts/) for LinkedIn

## LinkedIn post (draft)

> AI agents don't just generate text — they call tools. I built Agent Security Gate to enforce policy **before** tool execution: block doc exfiltration and SSRF, require approval for risky writes, and produce hash-chained audit evidence.  
> Try it free: `docker compose up` → https://github.com/giselleevita/agent-security-gate#try-it  
> Repo: https://github.com/giselleevita/agent-security-gate
