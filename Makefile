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
DOCKER_ANONYMOUS_CONFIG := $(ROOT)/infra/local/docker-anonymous
POSTGRES_IMAGE := postgres:18.4-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15
LOCAL_IMAGES := $(POSTGRES_IMAGE) redis:8.2.7-alpine@sha256:223b183cbc49f5ff48728e1fc52ccf101f05072decad2bd9867281a3c9bf75fd minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727 axllent/mailpit:v1.27.8@sha256:6abc8e633df15eaf785cfcf38bae48e66f64beecdc03121e249d0f9ec15f0707 nginx:1.29.5-alpine@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b python:3.12.13-alpine3.23@sha256:601d3d3797e90e2534782e69c85fafb7971b43f24c7b1b079b7e48dd435e458d ghcr.io/astral-sh/uv:0.11.28@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa
CLAMAV_IMAGE := clamav/clamav:1.4.3@sha256:75fb5fd95fcbe1d7e6d240c369c1572b686ee2c95949d1042b5148de8eddebb4
PROVIDER_RUNTIME_PYTHON := \
	$(patsubst $(ROOT)/%,%,$(wildcard $(ROOT)/services/api/provider_*.py)) \
	services/api/tool_governance.py \
	services/api/product_app.py \
	tests/g004

.PHONY: bootstrap lint-contracts typecheck-contracts test-openapi test-protocol-contracts test-artifact-contracts test-boundaries verify-spec verify-architecture test-local-config print-local-images prepare-postgres-image test-migrations test-rls test-upload test-artifacts test-science test-dry-lab test-product-ui test-provider-runtime provider-cleanup-sweep test-e2e-artifacts stack-up smoke-local stack-down ci-source-identity ci-validate ci-local test-retention check-generated-contracts test-security

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
	echo "toolchain: node 24.17.0, pnpm 11.12.0, python 3.12.13, uv 0.11.28"; \
	echo "bootstrap: ready (locked Python and pnpm dependencies installed locally)"

lint-contracts:
	@set -eu; \
	cd "$(ROOT)"; \
	"$(VENV)/bin/ruff" check packages/contracts/python tests/test_openapi_contract.py; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm contracts:lint

typecheck-contracts:
	@set -eu; \
	cd "$(ROOT)"; \
	"$(VENV)/bin/basedpyright" packages/contracts/python tests/test_openapi_contract.py; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm contracts:typecheck

test-openapi:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m unittest tests.test_openapi_contract -v; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" packages/contracts/python/tests -v; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm contracts:test; \
	$(MAKE) lint-contracts typecheck-contracts

test-protocol-contracts:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" \
		packages/contracts/python/tests/test_protocol_red.py \
		packages/contracts/python/tests/test_protocol_security_red.py \
		packages/contracts/python/tests/test_run_execution_protocol.py \
		packages/contracts/python/tests/test_approval_protocol.py \
		packages/contracts/python/tests/test_approval_security_protocol.py \
		packages/contracts/python/tests/test_sse_runtime_protocol.py -v; \
	MISE_DATA_DIR="$(MISE_DATA_DIR)" MISE_CACHE_DIR="$(MISE_CACHE_DIR)" MISE_CONFIG_DIR="$(MISE_CONFIG_DIR)" MISE_STATE_DIR="$(MISE_STATE_DIR)" MISE_CONFIG_FILE="$(MISE_CONFIG_FILE)" MISE_CEILING_PATHS="$(ROOT_PARENT)" mise exec -- pnpm exec vitest run --dir packages/contracts/tests protocols.test.ts; \
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
	PYTHONDONTWRITEBYTECODE=1 "$$python" -m tools.verify_spec "$(ROOT)/docs/requirements/requirements.yaml" "$(ROOT)/docs/spec/SPEC-v0.4.md"

verify-architecture:
	@set -eu; \
	cd "$(ROOT)"; \
	if [ -x "$(VENV)/bin/python" ]; then python="$(VENV)/bin/python"; else python="$$(command -v python3)"; fi; \
	PYTHONDONTWRITEBYTECODE=1 "$$python" -m unittest discover -s "$(ROOT)/tests" -p "test_architecture.py" -v; \
	PYTHONDONTWRITEBYTECODE=1 "$$python" "$(ROOT)/tools/verify_architecture.py" "$(ROOT)/docs/architecture"

test-local-config:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" tests/local_stack -v; \
	"$(VENV)/bin/ruff" check services/local tests/local_stack; \
	PYTHONPATH="$(ROOT)" "$(VENV)/bin/basedpyright" services/local tests/local_stack; \
	docker compose -f compose.yaml config --quiet

print-local-images:
	@printf '%s\n' $(LOCAL_IMAGES) $(CLAMAV_IMAGE)

prepare-postgres-image:
	@set -eu; \
	cd "$(ROOT)"; \
	command -v docker >/dev/null 2>&1 || { echo "error: Docker is required" >&2; exit 1; }; \
	docker_bin="$$(command -v docker)"; \
	docker info >/dev/null 2>&1 || { echo "error: Docker engine is unavailable" >&2; exit 1; }; \
	docker_host="$$(docker context inspect "$$(docker context show)" --format '{{.Endpoints.docker.Host}}')"; \
	DOCKER_HOST="$$docker_host" sh infra/local/pull-anonymous.sh "$$docker_bin" "$(POSTGRES_IMAGE)"

test-migrations: prepare-postgres-image
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)/packages/contracts/python:$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" \
		tests/connectors/test_registry.py \
		services/api/tests/persistence/test_schema_artifacts.py \
		services/api/tests/persistence/test_connector_registry.py \
		services/api/tests/persistence/test_principal.py \
		services/api/tests/persistence/test_upgrade_migrations.py \
		services/api/tests/persistence/test_migrations.py -v; \
	"$(VENV)/bin/ruff" check services/api/persistence services/api/migrations services/api/tests/persistence; \
	PYTHONPATH="$(ROOT)/packages/contracts/python:$(ROOT)" "$(VENV)/bin/basedpyright" services/api/persistence services/api/migrations services/api/tests/persistence

test-rls: prepare-postgres-image
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)/packages/contracts/python:$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" services/api/tests/persistence/test_rls*.py -v; \
	"$(VENV)/bin/ruff" check services/api/persistence services/api/migrations services/api/tests/persistence; \
	PYTHONPATH="$(ROOT)/packages/contracts/python:$(ROOT)" "$(VENV)/bin/basedpyright" services/api/persistence services/api/migrations services/api/tests/persistence

test-upload:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" tests/upload tests/local_stack/test_scanner.py -v; \
	"$(VENV)/bin/ruff" check services/api/upload tests/upload services/local/scanner.py tests/local_stack/test_scanner.py; \
	PYTHONPATH="$(ROOT)" "$(VENV)/bin/basedpyright" services/api/upload tests/upload services/local/scanner.py tests/local_stack/test_scanner.py

test-artifacts: prepare-postgres-image
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" \
		tests/artifacts \
		services/api/tests/persistence/test_artifact_composition.py \
		services/api/tests/persistence/test_artifact_composition_postgres.py \
		services/api/tests/persistence/test_artifact_production_http.py \
		services/api/tests/persistence/test_artifact_persistence.py \
		services/api/tests/persistence/test_artifact_persistence_races.py \
		services/api/tests/persistence/test_artifact_project_guards.py -v; \
	"$(VENV)/bin/ruff" check services/api/artifact_production_app.py \
		services/api/artifacts services/api/persistence/auth_sessions.py \
		tests/artifacts \
		services/api/tests/persistence/test_artifact_composition.py \
		services/api/tests/persistence/test_artifact_composition_postgres.py \
		services/api/tests/persistence/test_artifact_production_http.py \
		services/api/tests/persistence/test_artifact_persistence.py \
		services/api/tests/persistence/test_artifact_persistence_races.py \
		services/api/tests/persistence/test_artifact_project_guards.py; \
	PYTHONPATH="$(ROOT)" "$(VENV)/bin/basedpyright" \
		services/api/artifact_production_app.py services/api/artifacts \
		services/api/persistence/auth_sessions.py \
		tests/artifacts services/api/tests/persistence/test_artifact_composition.py \
		services/api/tests/persistence/test_artifact_composition_postgres.py \
		services/api/tests/persistence/test_artifact_production_http.py \
		services/api/tests/persistence/test_artifact_persistence.py \
		services/api/tests/persistence/test_artifact_persistence_races.py \
		services/api/tests/persistence/test_artifact_project_guards.py

test-science:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" PYTHONDONTWRITEBYTECODE=1 \
		"$(VENV)/bin/pytest" tests/science -v; \
	"$(VENV)/bin/ruff" check packages/science tests/science; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" \
		"$(VENV)/bin/basedpyright" packages/science tests/science
test-dry-lab:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" tests/g002 -v; \
	"$(VENV)/bin/ruff" check packages/science/science_workbench_science/vertical.py services/worker/dry_lab_vertical.py services/worker/__init__.py services/api/dry_lab_fixture.py tests/g002; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" "$(VENV)/bin/basedpyright" packages/science/science_workbench_science/vertical.py services/worker/dry_lab_vertical.py services/worker/__init__.py services/api/dry_lab_fixture.py tests/g002
test-product-ui:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" tests/g003 -v; \
	"$(VENV)/bin/ruff" check services/api/product_app.py services/api/product_tenancy.py services/api/product_dry_lab.py tests/g003; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" "$(VENV)/bin/basedpyright" services/api/product_app.py services/api/product_tenancy.py services/api/product_dry_lab.py tests/g003; \
	node --check apps/web/product/app.js; \
	$(MAKE) test-rls

test-provider-runtime:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" tests/g004 -v; \
	"$(VENV)/bin/ruff" check $(PROVIDER_RUNTIME_PYTHON); \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" "$(VENV)/bin/basedpyright" $(PROVIDER_RUNTIME_PYTHON); \
	node --check apps/web/product/app.js; \
	$(MAKE) test-rls

provider-cleanup-sweep:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m services.api.provider_cleanup_cli
test-e2e-artifacts:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/pytest" tests/artifact_ui -v; \
	"$(VENV)/bin/ruff" check services/api/artifact_ui_app.py services/api/artifact_ui_http.py services/api/product_artifact_fixtures.py services/api/product_artifact_http.py services/api/product_artifact_types.py services/api/product_artifact_validation.py services/api/product_artifact_views.py services/api/product_artifacts.py services/api/product_pdf_validation.py services/api/product_preview.py tools/run_artifact_ui_fixture.py tools/run_product_ui_fixture.py tests/artifact_ui; \
	PYTHONPATH="$(ROOT)/packages/science:$(ROOT)" "$(VENV)/bin/basedpyright" services/api/artifact_ui_app.py services/api/artifact_ui_http.py services/api/product_artifact_fixtures.py services/api/product_artifact_http.py services/api/product_artifact_types.py services/api/product_artifact_validation.py services/api/product_artifact_views.py services/api/product_artifacts.py services/api/product_pdf_validation.py services/api/product_preview.py tools/run_artifact_ui_fixture.py tools/run_product_ui_fixture.py tests/artifact_ui; \
	node --check apps/web/product/app.js; \
	node_modules/.bin/tsc -p tsconfig.json; \
	node node_modules/@playwright/test/cli.js test tests/e2e/artifacts.spec.ts tests/e2e/product-accessibility.spec.ts tests/e2e/product-journey.spec.ts tests/e2e/provider-settings.spec.ts tests/e2e/provider-settings-rendering.spec.ts
test-security:
	@set -eu; \
	cd "$(ROOT)"; \
	test -n "$(CASE)" || { echo "error: CASE is required" >&2; exit 1; }; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m tools.platform_policy.security_gate --case "$(CASE)"

stack-up: test-local-config
	@set -eu; \
	cd "$(ROOT)"; \
	command -v docker >/dev/null 2>&1 || { echo "error: Docker is required" >&2; exit 1; }; \
	docker_bin="$$(command -v docker)"; \
	docker info >/dev/null 2>&1 || { echo "error: Docker engine is unavailable" >&2; exit 1; }; \
	docker_host="$$(docker context inspect "$$(docker context show)" --format '{{.Endpoints.docker.Host}}')"; \
	for image in $(LOCAL_IMAGES); do \
		DOCKER_HOST="$$docker_host" sh infra/local/pull-anonymous.sh "$$docker_bin" "$$image"; \
	done; \
	DOCKER_HOST="$$docker_host" sh infra/local/pull-anonymous.sh "$$docker_bin" --platform linux/amd64 "$(CLAMAV_IMAGE)"; \
	docker compose -f compose.yaml up -d --build --pull never --wait --wait-timeout 300

smoke-local:
	@set -eu; \
	cd "$(ROOT)"; \
	command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }; \
	sh infra/local/smoke-local.sh

stack-down:
	@set -eu; \
	cd "$(ROOT)"; \
	docker compose -f compose.yaml down --volumes --remove-orphans

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

check-generated-contracts:
	@set -eu; \
	cd "$(ROOT)"; \
	PYTHONDONTWRITEBYTECODE=1 "$(VENV)/bin/python" -m tools.platform_policy.static_checks drift-scan "$(ROOT)"
