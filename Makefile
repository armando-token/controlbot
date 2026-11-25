UV ?= uv

.PHONY: doctor test test-n1 test-n2 test-n3 test-acceptance demo test-offline bench lint typecheck check

doctor:
	$(UV) run python -m src.doctor

test-n1:
	$(UV) run pytest tests/unit -m "not n2 and not n3"

test:
	$(MAKE) test-n1 && $(MAKE) test-n2 && $(MAKE) test-acceptance
	@if [ "$$(uname -s)" != "Linux" ]; then echo "[PENDING_N3_LINUX_ENV] Host is $$(uname -s); Linux N3 suite (A11 netns/iptables + real local LLM) is pending Linux target host. Run 'make test-n3' for skip reasons."; fi

lint:
	$(UV) run ruff check src lab benchmarks deploy tests/unit tests/integration tests/acceptance

typecheck:
	$(UV) run mypy src lab benchmarks deploy tests/unit tests/integration tests/acceptance

check:
	$(MAKE) doctor && $(MAKE) lint && $(MAKE) typecheck && $(MAKE) test

test-n2:
	$(UV) run pytest tests/integration -m "n2 and not n3" -v

test-n3:
	$(UV) run pytest tests/acceptance -m n3 -rs -v

test-acceptance:
	$(UV) run pytest tests/acceptance -m "acceptance and not n3" -v

demo:
	$(UV) run python -m src.demo

test-offline:
	$(UV) run python -m deploy.config --config deploy/install_config.yaml
	$(UV) run pytest tests/unit/test_deploy.py tests/unit/test_n3_probe.py tests/integration/test_local_http_model.py tests/acceptance/test_a01_a14.py tests/acceptance/test_m6_factory_deploy.py -k "a11 or deploy or local_http or factory" -m "not n3" -rs -v
	$(MAKE) test-n3
	@if [ "$$(uname -s)" != "Linux" ]; then echo "[PENDING_N3_LINUX_ENV] N1/N2 offline egress-allowlist & loopback checks passed on $$(uname -s); kernel netns/iptables & real local LLM checks remain PENDING_N3_LINUX_ENV (see scripts/verify_n3_linux.sh)."; fi

bench:
	$(UV) run python -m benchmarks.runner
