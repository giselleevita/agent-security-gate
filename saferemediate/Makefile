.PHONY: test phase0 phase1 pilot-dry canary mock-canary mock-pilot lint

test:
	PYTHONPATH=.:.. python3.11 -m pytest

phase0:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_phase0

phase1:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_phase1

pilot-dry:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --dry-run --provider mock --trials 5

mock-canary:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --provider mock --phase canary --trials 1 --no-resume

mock-pilot:
	PYTHONPATH=.:.. python3.11 -m saferemediate.run_pilot --provider mock --phase pilot --trials 5 --no-resume

lint:
	ruff check saferemediate tests
