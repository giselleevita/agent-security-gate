# Contributing

Thank you for your interest in contributing to Agent Security Gate.

## Getting started

```bash
git clone https://github.com/giselleevita/agent-security-gate
cd agent-security-gate
cp .env.example .env
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Start services:
```bash
docker compose up -d
```

Run tests:
```bash
pytest tests/
```

## Branch naming

| Type | Pattern | Example |
|---|---|---|
| Feature | `feat/description` | `feat/siem-integration` |
| Bug fix | `fix/description` | `fix/approval-self-approval-check` |
| Docs | `docs/description` | `docs/api-reference` |
| Policy | `policy/description` | `policy/add-s3-prefix-deny` |

## Issue labels

- `bug` — something is broken
- `enhancement` — new feature or policy
- `docs` — documentation gap
- `policy` — OPA Rego policy change
- `security` — security-relevant change
- `ci` — CI/CD related

## PR checklist

- [ ] `pytest tests/` passes
- [ ] New policies include a test in `tests/`
- [ ] New attack scenarios included in `benchmark/scenarios/scenarios.yaml`
- [ ] `.env.example` updated if new env vars added
- [ ] No real credentials or secrets committed
- [ ] README updated if API or config changes

## Code style

```bash
ruff check .
```
