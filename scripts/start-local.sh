#!/usr/bin/env bash
set -euo pipefail

if [ -f .env ]; then
  # shellcheck disable=SC1091
  source .env
fi

find_python_with_module() {
  local module="$1"
  local candidate
  local candidates=()

  if [ -n "${GUARDRAIL_PYTHON:-}" ]; then
    candidates+=("${GUARDRAIL_PYTHON}")
  fi
  candidates+=("python3" "/Applications/Xcode.app/Contents/Developer/usr/bin/python3" "/usr/bin/python3")

  for candidate in "${candidates[@]}"; do
    if command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ]; then
      if "$candidate" - "$module" <<'PY' >/dev/null 2>&1
import importlib.util
import sys

sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 1)
PY
      then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done

  printf '%s\n' "${GUARDRAIL_PYTHON:-python3}"
}

API_CMD=${GUARDRAIL_API_START_CMD:-"echo '[api] TODO: set GUARDRAIL_API_START_CMD in .env'"}
WEB_CMD=${GUARDRAIL_WEB_START_CMD:-"echo '[web] TODO: set GUARDRAIL_WEB_START_CMD in .env'"}
DEMO_CMD=${GUARDRAIL_DEMO_START_CMD:-"echo '[demo] TODO: set GUARDRAIL_DEMO_START_CMD in .env'"}
PROXY_CMD=${GUARDRAIL_PROXY_START_CMD:-"npm --prefix playwright-proxy run start"}
PYTHON_WITH_UVICORN="$(find_python_with_module uvicorn)"

if [ "${API_CMD}" = "echo '[api] TODO: set GUARDRAIL_API_START_CMD in .env'" ]; then
  API_CMD="${PYTHON_WITH_UVICORN} -m uvicorn backend.main:app --host ${API_HOST:-127.0.0.1} --port ${API_PORT:-8000}"
elif [[ "${API_CMD}" == uvicorn\ * ]]; then
  API_CMD="${PYTHON_WITH_UVICORN} -m ${API_CMD}"
elif [[ "${API_CMD}" == python3\ -m\ uvicorn* ]]; then
  API_CMD="${PYTHON_WITH_UVICORN}${API_CMD#python3}"
fi
if [ "${WEB_CMD}" = "echo '[web] TODO: set GUARDRAIL_WEB_START_CMD in .env'" ]; then
  WEB_CMD="npm run dev -- --host 127.0.0.1 --port 3000"
fi
if [ "${DEMO_CMD}" = "echo '[demo] TODO: set GUARDRAIL_DEMO_START_CMD in .env'" ]; then
  DEMO_CMD="npm --prefix demo-target run dev"
fi

check_port_available() {
  local name="$1"
  local port="$2"
  local pids=""

  if [ -z "$port" ]; then
    return 0
  fi

  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  fi

  if [ -n "$pids" ]; then
    echo "[$name] port $port is already in use by PID(s): ${pids//$'\n'/, }" >&2
    echo "Stop that process or change the ${name} port before running make up." >&2
    return 1
  fi
}

if [ "${GUARDRAIL_SKIP_PORT_CHECK:-false}" != "true" ]; then
  check_port_available "api" "${API_PORT:-8000}"
  check_port_available "web" "${WEB_PORT:-3000}"
  check_port_available "demo" "${DEMO_PORT:-7070}"
  if [ -d "playwright-proxy" ]; then
    check_port_available "proxy" "${PLAYWRIGHT_PROXY_PORT:-7071}"
  fi
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
