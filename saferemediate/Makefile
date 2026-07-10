.PHONY: test phase0 phase1 pilot-dry canary pilot lint

test:
	PYTHONPATH=.:.. python3.11 -m pytest

phase0:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_phase0

phase1:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_phase1

pilot-dry:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --dry-run --model gpt-4.1-mini-2025-04-14 --trials 5

canary:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --phase canary --model gpt-4.1-mini-2025-04-14 --trials 1 --no-resume

pilot:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --phase pilot --model gpt-4.1-mini-2025-04-14 --trials 5 --no-resume

lint:
	ruff check saferemediate tests
