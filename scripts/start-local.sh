#!/usr/bin/env bash
set -euo pipefail

if [ -f .env ]; then
  # shellcheck disable=SC1091
  source .env
fi

API_CMD=${GUARDRAIL_API_START_CMD:-"echo '[api] TODO: set GUARDRAIL_API_START_CMD in .env'"}
WEB_CMD=${GUARDRAIL_WEB_START_CMD:-"echo '[web] TODO: set GUARDRAIL_WEB_START_CMD in .env'"}
DEMO_CMD=${GUARDRAIL_DEMO_START_CMD:-"echo '[demo] TODO: set GUARDRAIL_DEMO_START_CMD in .env'"}
PROXY_CMD=${GUARDRAIL_PROXY_START_CMD:-"npm --prefix playwright-proxy run start"}

if [ "${API_CMD}" = "echo '[api] TODO: set GUARDRAIL_API_START_CMD in .env'" ]; then
  API_CMD="uvicorn backend.main:app --host ${API_HOST:-127.0.0.1} --port ${API_PORT:-8000}"
fi
if [ "${WEB_CMD}" = "echo '[web] TODO: set GUARDRAIL_WEB_START_CMD in .env'" ]; then
  WEB_CMD="npm run dev -- --host 127.0.0.1 --port 3000"
fi
if [ "${DEMO_CMD}" = "echo '[demo] TODO: set GUARDRAIL_DEMO_START_CMD in .env'" ]; then
  DEMO_CMD="npm --prefix demo-target run dev"
fi

pids=()

start_bg() {
  local name="$1"
  local cmd="$2"

  echo "[$name] starting: $cmd"
  bash -lc "$cmd" &
  pids+=("$!")
}

cleanup() {
  echo "Stopping local services..."
  for pid in "${pids[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
}

trap cleanup EXIT INT TERM

start_bg "api" "$API_CMD"
start_bg "web" "$WEB_CMD"
start_bg "demo" "$DEMO_CMD"
if [ -d "playwright-proxy" ]; then
  start_bg "proxy" "$PROXY_CMD"
fi

echo "Local startup running. Press Ctrl+C to stop."
wait
