# GitHub profile setup

Manual steps that cannot be automated via the GitHub API.

## Pin 6 repositories

GitHub does not expose repository pinning via API. Pin these in **Profile → Customize your pins**:

1. [agent-security-gate](https://github.com/giselleevita/agent-security-gate)
2. [security-compliance-copilot](https://github.com/giselleevita/security-compliance-copilot)
3. [vendor-red-team-passport](https://github.com/giselleevita/vendor-red-team-passport)
4. [proofrail-evidence-api](https://github.com/giselleevita/proofrail-evidence-api)
5. [secure-docs-aws](https://github.com/giselleevita/secure-docs-aws)
6. [sai-platform](https://github.com/giselleevita/sai-platform)

Verify: `./scripts/check_visibility_sprint.sh` (from agent-security-gate repo)

## Bio

```
AgentOps & AI security platform engineer · Policy enforcement for LLM tool calls · OPA, FastAPI, audit/eval systems · Copenhagen
```

## Live demo URL

After Fly deploy, update profile README **Live demo** line with `https://asg-demo.fly.dev` (or your app name).
