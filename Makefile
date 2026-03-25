SCENARIOS=benchmark/scenarios/scenarios.yaml

.PHONY: eval test lint

eval:
	python -m benchmark.runner --scenarios $(SCENARIOS) --summary results/summary.json

test:
	pytest

lint:
	ruff check .
