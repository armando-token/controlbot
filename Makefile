UV ?= uv

.PHONY: doctor test test-n1 test-n2 test-acceptance demo test-offline bench lint typecheck check

doctor:
	$(UV) run python -m src.doctor

test-n1:
	$(UV) run pytest tests/unit -m "not n2 and not n3"

test:
	@echo "[M1_SCOPE] Running N1 unit suite; N2/N3 suites pending M3/M4."
	$(MAKE) test-n1

lint:
	$(UV) run ruff check src tests

typecheck:
	$(UV) run mypy src tests

check:
	$(MAKE) doctor && $(MAKE) lint && $(MAKE) typecheck && $(MAKE) test

test-n2:
	@echo "[NOT_IMPLEMENTED: M3] N2 integration tests require lab/ and src/adapters/." && exit 2

test-acceptance:
	@echo "[NOT_IMPLEMENTED: M4] Acceptance suite A01-A14 scheduled for M4." && exit 2

demo:
	@echo "[NOT_IMPLEMENTED: M4] Pump 34 end-to-end demo scheduled for M4." && exit 2

test-offline:
	@echo "[PENDING_N3_LINUX_ENV: M6] Offline Linux/LAN test harness scheduled for M6 (requires Linux network isolation)." && exit 2

bench:
	@echo "[NOT_IMPLEMENTED: M5] Comparative >=12-scenario benchmark scheduled for M5." && exit 2
