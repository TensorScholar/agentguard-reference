.PHONY: verify tests lint typecheck demo release

PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE = 1
export PYTHONPATH = src

tests:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check --no-cache src tests examples scripts

typecheck:
	$(PYTHON) -m mypy --cache-dir=/dev/null src

demo:
	$(PYTHON) -m agentguard_reference demo

verify: tests lint typecheck demo

release: verify
	$(PYTHON) scripts/build_release.py
