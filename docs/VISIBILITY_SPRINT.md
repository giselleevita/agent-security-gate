# Visibility Sprint — 30-day checklist

Execute after the [90-day repositioning plan](https://github.com/giselleevita/agent-security-gate). Repo work is done; this sprint makes it **clickable** for recruiters.

## Week 1 — Clickable in 5 minutes

- [ ] **Pin 6 repos** on GitHub profile (manual — no API):
  1. `agent-security-gate`
  2. `security-compliance-copilot`
  3. `vendor-red-team-passport`
  4. `proofrail-evidence-api`
  5. `secure-docs-aws`
  6. `sai-platform`
- [ ] **Fly demo live**
  ```bash
  brew install flyctl
  flyctl auth login
  ./scripts/fly_demo_bootstrap.sh
  ```
- [ ] Update **Live demo** URL in [profile README](https://github.com/giselleevita/giselleevita) and [README.md](../README.md) Try it table
- [ ] Merge automated **benchmark snapshot PRs** when `publish-benchmark` workflow opens them
- [ ] Confirm `sai-platform` has no secrets in history (see [sai-platform-public-audit.md](./sai-platform-public-audit.md))

**Verify:** `scripts/check_visibility_sprint.sh`

## Week 2 — Proof you can explain it

- [ ] Record **3-min demo video** — script: [DEMO_VIDEO.md](./DEMO_VIDEO.md)
- [ ] Embed video link in README + profile README
- [ ] Record **terminal GIF** (4 curl attacks + audit verify); add to `docs/assets/`
- [ ] Publish blog on **dev.to** — [cross-posts/devto.md](./blog/cross-posts/devto.md)
- [ ] Post on **LinkedIn** — [cross-posts/linkedin.md](./blog/cross-posts/linkedin.md)

## Week 3 — Apply with a packet

Build one recruiter packet linking:

1. Live Fly URL
2. [agent-security-gate](https://github.com/giselleevita/agent-security-gate)
3. Demo video
4. Blog post
5. [vendor-red-team-passport](https://github.com/giselleevita/vendor-red-team-passport)
6. [security-compliance-copilot](https://github.com/giselleevita/security-compliance-copilot)

Apply to **10 roles** — see [APPLICATIONS.md](./APPLICATIONS.md).

## Week 4 — One external signal

- [ ] One OSS PR (OPA example, LangGraph docs, or FastAPI security recipe)
- [ ] Add PR link to profile README

## Stop doing

- New unrelated repos
- ASG feature work until demo is live
- Mass repo grooming days

## Success criteria

A hiring manager in 5 minutes: **6 pins → video/GIF → live demo → blog → clear AgentOps positioning**.
