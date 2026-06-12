SCENARIOS=benchmark/scenarios/scenarios.yaml
EVIDENCE_DIR=results/evidence

.PHONY: eval gate evidence verify-evidence migrate test integration lint security

eval:
	python3 -m benchmark.runner --scenarios $(SCENARIOS) --summary results/summary.json

gate: eval
	python3 -m benchmark.gate --summary results/summary.json --thresholds ci/thresholds.yaml

evidence: eval
	python3 -m benchmark.evidence create --artifact results/summary.json --output $(EVIDENCE_DIR)

verify-evidence:
	python3 -m benchmark.evidence verify --bundle $(EVIDENCE_DIR)

migrate:
	python3 -m scripts.migrate_db

test:
	pytest -m "not integration"

integration:
	pytest -m integration

lint:
	ruff check .

security:
	bandit -r app adapters audit benchmark gateway approvals scripts -ll
	pip-audit --skip-editable --progress-spinner off
