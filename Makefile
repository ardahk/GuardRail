SHELL := /bin/bash
.ONESHELL:
.DEFAULT_GOAL := help

ENV_FILE ?= .env
PYTHON ?= $(shell for p in python3 /usr/bin/python3; do $$p -c 'import pytest' >/dev/null 2>&1 && { echo $$p; break; }; done)
PYTEST ?= $(PYTHON) -m pytest

help:
	@echo "GuardRail DX targets"
	@echo "  make install            # Install backend + frontend + demo dependencies"
	@echo "  make env-check          # Validate .env exists"
	@echo "  make up                 # Start the local full-stack demo"
	@echo "  make test               # Run backend and browser proxy tests"
	@echo "  make test-unit          # Run backend unit tests"
	@echo "  make test-integration   # Run backend integration tests"
	@echo "  make test-browser       # Run browser proxy reliability tests"
	@echo "  make fixtures           # Start the 12-pattern local chatbot fixture matrix"
	@echo "  make test-browser-matrix # Run 20x12 live browser soak acceptance gate"
	@echo "  make test-browser-faults # Run live browser degradation and cleanup gates"
	@echo "  make calibrate-judge     # Enforce golden-set judge quality thresholds"

install:
	@python3 -m pip install -r config/backend/requirements-dev.txt
	@npm install
	@npm --prefix demo-target install
	@npm --prefix playwright-proxy install

env-check:
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo "Missing $(ENV_FILE). Copy .env.example to $(ENV_FILE)."; \
		exit 1; \
	fi

test-unit:
	@$(PYTEST) -q tests/unit

test-integration:
	@$(PYTEST) -q tests/integration

test-browser:
	@npm --prefix playwright-proxy test

fixtures:
	@npm --prefix playwright-proxy run fixtures

test-browser-matrix:
	@npm --prefix playwright-proxy run test:matrix

test-browser-faults:
	@npm --prefix playwright-proxy run test:faults

calibrate-judge:
	@$(PYTHON) scripts/calibrate-judge.py

test: test-unit test-integration test-browser

up: env-check
	@bash scripts/start-local.sh
