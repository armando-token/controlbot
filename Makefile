UV ?= uv

.PHONY: doctor test test-n1 test-n2 test-acceptance demo test-offline bench lint typecheck check

doctor:
	$(UV) run python -m src.doctor

test-n1:
	$(UV) run pytest tests/unit -m "not n2 and not n3"

test:
	$(MAKE) test-n1 && $(MAKE) test-n2 && $(MAKE) test-acceptance

lint:
	$(UV) run ruff check src lab benchmarks tests/unit tests/integration tests/acceptance

typecheck:
	$(UV) run mypy src lab benchmarks tests/unit tests/integration tests/acceptance

check:
	$(MAKE) doctor && $(MAKE) lint && $(MAKE) typecheck && $(MAKE) test

test-n2:
	$(UV) run pytest tests/integration -m "n2 and not n3" -v

test-acceptance:
	$(UV) run pytest tests/acceptance -m "acceptance and not n3" -v

demo:
	$(UV) run python -m src.demo

test-offline:
	@echo "[PENDING_N3_LINUX_ENV: M6] Offline Linux/LAN test harness scheduled for M6 (requires Linux network isolation)." && exit 2

bench:
	$(UV) run python -m benchmarks.runner
