SHELL := /bin/sh

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ROOT_PARENT := $(abspath $(ROOT)/..)
MISE_DATA_DIR := $(ROOT)/.tools/mise
MISE_CACHE_DIR := $(ROOT)/.cache/mise
MISE_CONFIG_DIR := $(ROOT)/.tools/mise-config
MISE_CONFIG_FILE := $(ROOT)/mise.toml
MISE_STATE_DIR := $(ROOT)/.tools/mise-state
UV_CACHE_DIR := $(ROOT)/.cache/uv
VENV := $(ROOT)/.venv
PNPM_ROOT := $(ROOT)/.tools/pnpm
PNPM_HOME := $(PNPM_ROOT)/home
PNPM_STORE_DIR := $(PNPM_ROOT)/store
PNPM_CACHE_DIR := $(ROOT)/.cache/pnpm
NODE_MODULES := $(ROOT)/node_modules
CONTRACT_NODE_MODULES := $(ROOT)/packages/contracts/node_modules


.PHONY: bootstrap lint-contracts typecheck-contracts test-protocol-contracts test-artifact-contracts test-boundaries verify-spec verify-architecture test-artifacts test-science test-local-workbench check-quarantine ci-source-identity ci-validate ci-local test-retention test-security

bootstrap:
	@set -eu; \
	command -v mise >/dev/null 2>&1 || { echo "error: mise is required" >&2; exit 1; }; \
	cd "$(ROOT)"; \
	for path in "$(ROOT)/.tools" "$(ROOT)/.cache" "$(MISE_DATA_DIR)" "$(MISE_CONFIG_DIR)" "$(MISE_STATE_DIR)" "$(UV_CACHE_DIR)" "$(VENV)" "$(PNPM_ROOT)" "$(PNPM_HOME)" "$(PNPM_STORE_DIR)" "$(PNPM_CACHE_DIR)" "$(NODE_MODULES)" "$(CONTRACT_NODE_MODULES)"; do \
		test ! -L "$$path" || { echo "error: local tool path is a symlink: $$path" >&2; exit 1; }; \
	done; \
	mkdir -p "$(PNPM_HOME)" "$(PNPM_STORE_DIR)" "$(PNPM_CACHE_DIR)"; \
	export MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" UV_CACHE_DIR="$(UV_CACHE_DIR)"; \
	mise trust --yes "$(ROOT)/mise.toml"; \
	export MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)"; \
	mise install --yes; \
	test "$$(mise exec -- node --version)" = "v24.17.0"; \
	test "$$(mise exec -- pnpm --version)" = "11.12.0"; \
	test "$$(mise exec -- python --version)" = "Python 3.12.13"; \
	case "$$(mise exec -- uv --version)" in "uv 0.11.28"|"uv 0.11.28 "*) ;; *) exit 1 ;; esac; \
	if [ -e "$(VENV)" ]; then \
		test -x "$(VENV)/bin/python" || { echo "error: existing .venv is incomplete" >&2; exit 1; }; \
		test "$$($(VENV)/bin/python --version)" = "Python 3.12.13" || { echo "error: existing .venv uses the wrong Python" >&2; exit 1; }; \
	else \
		mise exec -- uv venv --python "$$(mise which python)" "$(VENV)"; \
	fi; \
	test -f "$(ROOT)/uv.lock" || { echo "error: uv.lock is required" >&2; exit 1; }; \
	test -f "$(ROOT)/pnpm-lock.yaml" || { echo "error: pnpm-lock.yaml is required" >&2; exit 1; }; \
	mise exec -- uv sync --locked; \
	PNPM_HOME="$(PNPM_HOME)" mise exec -- pnpm --config.cache-dir="$(PNPM_CACHE_DIR)" install --frozen-lockfile --store-dir="$(PNPM_STORE_DIR)"; \
	mise exec -- node node_modules/@playwright/test/cli.js install chromium; \
	if [ "$$(uname -s)" = "Linux" ] && command -v fc-list >/dev/null 2>&1 && ! fc-list :lang=ko | grep -q .; then \
		echo "bootstrap: installing Korean fonts (WCAG target-size and CJK reflow gates measure real glyph metrics)"; \
		sudo apt-get install -y fonts-noto-cjk fonts-noto-cjk-extra; \
	fi; \
	echo "toolchain: node 24.17.0, pnpm 11.12.0, python 3.12.13, uv 0.11.28"; \
	echo "bootstrap: ready (locked Python and pnpm dependencies installed locally)"

lint-contracts:
	@set -eu; \
	cd "$(ROOT)"; \
	"$(VENV)/bin/ruff" check packages/contracts/python; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm contracts:lint

typecheck-contracts:
	@set -eu; \
	cd "$(ROOT)"; \
	"$(VENV)/bin/basedpyright" packages/contracts/python; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm contracts:typecheck

test-protocol-contracts:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" \
		packages/contracts/python/tests/test_protocol_red.py \
		packages/contracts/python/tests/test_protocol_security_red.py \
		packages/contracts/python/tests/test_run_execution_protocol.py \
		packages/contracts/python/tests/test_approval_protocol.py \
		packages/contracts/python/tests/test_approval_security_protocol.py \
		packages/contracts/python/tests/test_sse_runtime_protocol.py \
		packages/contracts/python/tests/test_run_event_immutability.py \
		packages/contracts/python/tests/test_contract_models.py -v; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm exec vitest run --dir packages/contracts/tests protocols.test.ts run-event-immutability.test.ts; \
	"$(VENV)/bin/ruff" check packages/contracts/python/science_workbench_contracts/protocols packages/contracts/python/tests/protocol_fixtures.py packages/contracts/python/tests/test_*protocol*.py; \
	"$(VENV)/bin/basedpyright" packages/contracts/python/science_workbench_contracts/protocols packages/contracts/python/tests/protocol_fixtures.py packages/contracts/python/tests/test_*protocol*.py; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm exec biome check packages/contracts/src/protocols packages/contracts/tests/protocols.test.ts; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm contracts:typecheck

test-artifact-contracts:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" \
		packages/contracts/python/tests/test_scientific_artifact_contracts.py \
		packages/contracts/python/tests/test_artifact_cas_export.py \
		packages/contracts/python/tests/test_artifact_version_review_transitions.py \
		packages/contracts/python/tests/test_export_manifest_attacks.py \
		packages/contracts/python/tests/test_dry_lab_integrity_attacks.py -v; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm exec vitest run --dir packages/contracts/tests scientific-artifact-contracts.test.ts artifact-cas-export.test.ts dry-lab-integrity-attacks.test.ts export-manifest-attacks.test.ts review-findings-cas.test.ts; \
	$(MAKE) lint-contracts typecheck-contracts

test-boundaries:
	@set -eu; \
	cd "$(ROOT)"; \
	test -f "$(ROOT)/tools/check_boundaries.py" || { echo "error: tools/check_boundaries.py is missing" >&2; exit 1; }; \
	if [ -x "$(VENV)/bin/python" ]; then python="$(VENV)/bin/python"; else python="$$(command -v python3)"; fi; \
	"$$python" -m unittest discover -s "$(ROOT)/tests" -p "test_boundaries.py" -v; \
	"$$python" "$(ROOT)/tools/check_boundaries.py" "$(ROOT)"

verify-spec:
	@set -eu; \
	cd "$(ROOT)"; \
	if [ -x "$(VENV)/bin/python" ]; then python="$(VENV)/bin/python"; else python="$$(command -v python3)"; fi; \
	PYTHONDONTWRITEBYTECODE=1 "$$python" -m unittest discover -s "$(ROOT)/tools/tests" -p "test_verify_spec.py" -v; \
	PYTHONDONTWRITEBYTECODE=1 "$$python" -m tools.verify_spec "$(ROOT)/docs/requirements/requirements.yaml" "$(ROOT)/docs/spec/SPEC-v0.5.md"

verify-architecture:
	@set -eu; \
	cd "$(ROOT)"; \
	if [ -x "$(VENV)/bin/python" ]; then python="$(VENV)/bin/python"; else python="$$(command -v python3)"; fi; \
	PYTHONDONTWRITEBYTECODE=1 "$$python" -m unittest discover -s "$(ROOT)/tests" -p "test_architecture.py" -v; \
	PYTHONDONTWRITEBYTECODE=1 "$$python" "$(ROOT)/tools/verify_architecture.py" "$(ROOT)/docs/architecture"

test-artifacts:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" tests/artifacts -v; \
	"$(VENV)/bin/ruff" check services/api/artifacts tests/artifacts; \
	PYTHONPATH="$(ROOT)" "$(VENV)/bin/basedpyright" services/api/artifacts tests/artifacts

test-science:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" PYTHONDONTWRITEBYTECODE=1 \
		"$(VENV)/bin/pytest" tests/science -v; \
	"$(VENV)/bin/ruff" check packages/science tests/science; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" \
		"$(VENV)/bin/basedpyright" packages/science tests/science

check-quarantine:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m tools.platform_policy.saas_quarantine "$(ROOT)"

test-local-workbench:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)/apps/local:$(ROOT)/packages/science:$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" apps/local/tests -v; \
	"$(VENV)/bin/ruff" check apps/local tests/e2e/local_workbench_fixture.py; \
	"$(VENV)/bin/ruff" format --check apps/local tests/e2e/local_workbench_fixture.py; \
	PYTHONPATH="$(ROOT)/apps/local:$(ROOT)/packages/science:$(ROOT)" "$(VENV)/bin/basedpyright" apps/local tests/e2e/local_workbench_fixture.py; \
	node --check apps/web/local/app.js

test-security:
	@set -eu; \
	cd "$(ROOT)"; \
	test -n "$(CASE)" || { echo "error: CASE is required" >&2; exit 1; }; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m tools.platform_policy.security_gate --case "$(CASE)"

ci-source-identity:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m tools.platform_policy.ci_source_identity "$(ROOT)"

ci-validate:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m tools.platform_policy.ci_validation "$(ROOT)"

ci-local:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m tools.platform_policy.ci_runner "$(ROOT)"

test-retention:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m pytest tests/platform/test_retention.py -v; \
	"$(VENV)/bin/ruff" check tools/platform_policy/models.py tools/platform_policy/retention.py tests/platform/test_retention.py; \
	"$(VENV)/bin/basedpyright" tools/platform_policy/models.py tools/platform_policy/retention.py tests/platform/test_retention.py
