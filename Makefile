SCENARIOS=benchmark/scenarios/scenarios.yaml
EVIDENCE_DIR=results/evidence

.PHONY: eval compare gate evidence verify-evidence verify migrate test integration lint security agentdojo-development agentdojo-development-baselines agentdojo-heldout

eval:
	python3 -m benchmark.runner --scenarios $(SCENARIOS) --summary results/summary.json

compare:
	python3 -m benchmark.runner --scenarios $(SCENARIOS) --baseline compare --runs 5 --summary results/summary.json --comparison results/comparison.json --report results/benchmark-report.md

gate: eval
	python3 -m benchmark.gate --summary results/summary.json --thresholds ci/thresholds.yaml

evidence: eval
	python3 -m benchmark.evidence create --artifact results/summary.json --output $(EVIDENCE_DIR)

verify-evidence:
	python3 -m benchmark.evidence verify --bundle $(EVIDENCE_DIR)

verify:
	./scripts/verify.sh

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

agentdojo-development:
	python3 -m scripts.run_agentdojo_benchmark --phase development --mode asg --output-dir results/agentdojo/development/asg

agentdojo-development-baselines:
	python3 -m scripts.run_agentdojo_benchmark --phase development --mode no-authorizer --output-dir results/agentdojo/development/no-authorizer
	python3 -m scripts.run_agentdojo_benchmark --phase development --mode tool-filter --output-dir results/agentdojo/development/tool-filter

agentdojo-heldout:
	python3 -m scripts.run_agentdojo_benchmark --phase heldout --mode asg --output-dir results/agentdojo/heldout/asg
