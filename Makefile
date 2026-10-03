.PHONY: tests lint typecheck demo build archive-check verify release

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

build:
	$(PYTHON) scripts/build_release.py

# Runs only after `build`. Fail-closed: a missing archive, a stale archive, or an
# archive that does not carry the Core relationship fails here.
#
# Two layers. `scripts/validate_archive.py` is tracked and mandatory, and needs no
# private identifier. `.release/guard.py` is untracked by necessity -- it holds the
# exact markers -- and adds the exact check when present on the maintainer's machine.
archive-check:
	@if [ -f .release/guard.py ]; then $(PYTHON) -m ruff check --no-cache .release; fi
	$(PYTHON) scripts/validate_archive.py
	@if [ -f .release/guard.py ]; then \
		$(PYTHON) .release/guard.py; \
	else \
		echo "archive-check: exact private-marker layer NOT RUN (.release/guard.py absent)"; \
	fi

verify: tests lint typecheck demo

release: verify build archive-check