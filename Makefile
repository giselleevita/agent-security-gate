SCENARIOS=benchmark/scenarios/scenarios.yaml
LATENCY_RATE_LIMIT=100000
EVIDENCE_DIR=results/evidence

.PHONY: eval compare gate evidence verify-evidence verify migrate test integration lint security agentdojo-development agentdojo-development-baselines agentdojo-heldout agentdojo-latency agentdojo-opa-down agentdojo-evidence agentdojo-quality-baseline agentdojo-quality-variant agentdojo-quality-smoke agentdojo-quality-compare

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

# Raises the gateway decide rate limit for the replay, then restores the default.
agentdojo-latency:
	DECIDE_RATE_LIMIT_MAX=$(LATENCY_RATE_LIMIT) docker compose up -d gateway
	DECIDE_RATE_LIMIT_MAX=$(LATENCY_RATE_LIMIT) python3 -m scripts.measure_authorization_latency --run results/agentdojo/development/asg --output results/agentdojo/authorization-latency.json
	docker compose up -d gateway

# Requires the OPA container to be stopped first: docker compose stop opa
agentdojo-opa-down:
	python3 -m scripts.measure_authorization_latency --run results/agentdojo/development/asg --expect unavailable --repeats 1 --warmup 0 --output results/agentdojo/authorization-opa-down.json

agentdojo-evidence:
	python3 -m scripts.build_agentdojo_evidence

QUALITY_MODE ?= no-authorizer
QUALITY_DIR = results/agentdojo/quality

agentdojo-quality-baseline:
	python3 -m scripts.run_agentdojo_benchmark --phase development --mode $(QUALITY_MODE) --output-dir $(QUALITY_DIR)/baseline

# Cheap wiring check before committing an hour of inference: make agentdojo-quality-smoke VARIANT=v3-retry-empty-response
agentdojo-quality-smoke:
	python3 -m scripts.run_agentdojo_benchmark --phase development --mode $(QUALITY_MODE) --variant $(VARIANT) --limit 1 --output-dir $(QUALITY_DIR)/smoke-$(VARIANT)

# make agentdojo-quality-variant VARIANT=v3-retry-empty-response
agentdojo-quality-variant:
	python3 -m scripts.run_agentdojo_benchmark --phase development --mode $(QUALITY_MODE) --variant $(VARIANT) --output-dir $(QUALITY_DIR)/$(VARIANT)

agentdojo-quality-compare:
	python3 -m scripts.compare_agent_quality --baseline $(QUALITY_DIR)/baseline --run $(QUALITY_DIR)/$(VARIANT)
