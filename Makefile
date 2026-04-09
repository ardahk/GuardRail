SHELL := /bin/bash
.ONESHELL:
.DEFAULT_GOAL := help

ENV_FILE ?= .env
PYTEST ?= pytest

help:
	@echo "GuardRail DX targets"
	@echo "  make install            # Install backend + frontend + demo dependencies"
	@echo "  make env-check          # Validate .env exists"
	@echo "  make up                 # Start local full-stack demo (placeholder runner)"
	@echo "  make test               # Run unit + (optionally) integration skeletons"
	@echo "  make test-unit          # Run unit skeletons"
	@echo "  make test-integration   # Run integration skeletons"

install:
	@python3 -m pip install -r config/backend/requirements-dev.txt
	@npm install
	@npm --prefix demo-target install
	@npm --prefix playwright-proxy install
	@npx --prefix playwright-proxy playwright install chromium

env-check:
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo "Missing $(ENV_FILE). Copy .env.example to $(ENV_FILE)."; \
		exit 1; \
	fi

test-unit:
	@$(PYTEST) -q tests/unit

test-integration:
	@$(PYTEST) -q tests/integration

test: test-unit test-integration

up: env-check
	@bash scripts/start-local.sh
