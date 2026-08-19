#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_PROJECT="asg-verify-$$"
OPA_CONTAINER="${COMPOSE_PROJECT}-opa-check"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cleanup() {
  docker rm --force "${OPA_CONTAINER}" >/dev/null 2>&1 || true
  docker compose --project-name "${COMPOSE_PROJECT}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cd "${REPO_ROOT}"

"${PYTHON_BIN}" -m ruff check .
"${PYTHON_BIN}" -m pip_audit --requirement requirements.lock --progress-spinner off
"${PYTHON_BIN}" -m pip_audit --requirement requirements-dev.lock --progress-spinner off
"${PYTHON_BIN}" -m bandit -r app adapters audit benchmark gateway approvals scripts -ll

# Use the digest-pinned runtime so local verification does not depend on a host OPA binary.
docker run --detach \
  --name "${OPA_CONTAINER}" \
  --publish 127.0.0.1:8181:8181 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --volume "${REPO_ROOT}/policies:/policies:ro" \
  openpolicyagent/opa:1.19.1-static@sha256:32bf41d914b1505fea13303f60587cc57bdd2902262177585fb208f5dde76d32 \
  run --server --addr :8181 /policies >/dev/null
for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8181/health >/dev/null; then
    break
  fi
  sleep 1
done
curl -sf http://127.0.0.1:8181/health >/dev/null

docker run --rm \
  --volume "${REPO_ROOT}:/workspace:ro" \
  openpolicyagent/opa:1.19.1-static@sha256:32bf41d914b1505fea13303f60587cc57bdd2902262177585fb208f5dde76d32 \
  check --strict --v1-compatible /workspace/policies
docker run --rm \
  --volume "${REPO_ROOT}:/workspace:ro" \
  openpolicyagent/opa:1.19.1-static@sha256:32bf41d914b1505fea13303f60587cc57bdd2902262177585fb208f5dde76d32 \
  test /workspace/policies

DATABASE_URL="postgresql://asg:asg@127.0.0.1:1/asg" \
REDIS_URL="redis://127.0.0.1:1/0" \
OPA_URL="http://127.0.0.1:8181" \
"${PYTHON_BIN}" -m pytest -m "not integration"

OPA_URL="http://127.0.0.1:8181" \
"${PYTHON_BIN}" -m benchmark.runner \
  --scenarios benchmark/scenarios/scenarios.yaml \
  --summary results/summary.json
"${PYTHON_BIN}" -m benchmark.gate \
  --summary results/summary.json \
  --thresholds ci/thresholds.yaml

ASG_UID="$(id -u)" ASG_GID="$(id -g)" \
docker compose --project-name "${COMPOSE_PROJECT}" up -d --build
for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8000/health/ready >/dev/null; then
    break
  fi
  sleep 2
done
curl -sf http://127.0.0.1:8000/health/ready >/dev/null
"${PYTHON_BIN}" -m pytest -m integration --timeout=30
