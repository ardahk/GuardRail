# GuardRail

**AI red-team autopilot**

GuardRail stress-tests customer-facing chatbots with parallel jailbreak attempts, scores real risk in real time, then ships a hardened prompt diff you can apply in one click. GuardRail is a continuous red-team console for LLM apps. We attack your bot in parallel, detect exactly where it leaks, auto-generate a hardened system prompt, and rerun instantly to prove risk reduction.

**Can your AI withstand attacks?**

---

## Why GuardRail?

- Runs **multi-lane adversarial attacks** (prompt leak, data exfil, persona hijack, scope bypass, multi-turn poisoning)
- Shows a **live security scoreboard** while attacks are happening
- Generates a **targeted prompt patch** from observed failures
- Supports **apply-and-rerun** to prove measurable improvement immediately
- Works locally with a built-in vulnerable target (`demo-target/`) for reliable storytelling

---

## Key features

- FastAPI orchestration engine with async lane execution
- Attack library loaded from JSON/YAML in `backend/attacks/`
- OpenAI-compatible target adapter (`/v1/chat/completions`)
- CloakBrowser-backed local browser proxy for owned website chatbot testing
- LLM judge + mitigation generation pipeline
- Adaptive attacker prompts with multi-turn escalation + fallback steps
- Real-time websocket events (`run_started`, `attack_sent`, `judge_completed`, etc.)
- React + Tailwind dashboard with lane cards, risk metrics, and prompt workbench

---

## System architecture

1. **Attack Orchestrator** selects attacks by intensity and depth.
2. **Target Adapter** sends adversarial messages to victim model/API.
3. **Judge** scores each response (`pass`, `partial_fail`, `critical_fail`) with severity.
4. **Mitigation Engine** builds patched prompt from breached lanes.
5. **Apply & Rerun** updates the target prompt and launches a fresh run.

---

## Quickstart

### 1) Install

```bash
make install
```

Browser mode requires Node.js 20 or newer. The first CloakBrowser run downloads
a Chromium binary of roughly 200 MB into the local CloakBrowser cache.

### 2) Configure env

```bash
cp .env.example .env
```

### 3) Set model keys (minimum)

```dotenv
# Used by attacker/judge/mitigation pipeline
OPENAI_API_KEY=your_key_here
SECURITY_JUDGE_MODEL=gpt-5.4-mini
ATTACKER_MODEL=gpt-5.4-mini

# Victim model used by demo target
VICTIM_MODEL=gpt-5.4-nano
```

You can also run Gemini victims by setting `GEMINI_API_KEY` + a Gemini `VICTIM_MODEL`.

### Browser mode

GuardRail's website testing mode is for local, owned, or explicitly authorized
chatbot sites. It uses the existing `playwright-proxy/` service API, backed by
CloakBrowser by default:

```dotenv
BROWSER_ENGINE=cloakbrowser
CLOAKBROWSER_HEADLESS=true
CLOAKBROWSER_HUMANIZE=true
CLOAKBROWSER_AUTO_UPDATE=false
```

For owned sites that need cookies or local storage across a run, set a local
profile root:

```dotenv
CLOAKBROWSER_PROFILE_DIR=/tmp/guardrail-cloak-profiles
```

This does not add CAPTCHA solving, proxy rotation, or permission to test
third-party sites.

Before a website run, GuardRail requires the operator to confirm ownership or
explicit authorization. Use **Run safe preflight** to inspect the detected chat
context, selectors, widget fingerprint, and capture confidence without sending
an adversarial message. Deterministic DOM/accessibility discovery is always the
default; model-assisted browser fallback is explicit and opt-in.

Outbound target validation blocks credentials in URLs, link-local and reserved
addresses, and private-network destinations by default. Loopback remains
available for the inert fixture suite. To assess an authorized internal chatbot,
set `GUARDRAIL_ALLOW_PRIVATE_TARGETS=true` explicitly and keep GuardRail on a
trusted operator-controlled host.

### Reliability fixtures

The browser proxy includes twelve local, inert chatbot patterns for regression
testing (launchers, iframes, shadow DOM, contenteditable, streaming, replaced
nodes, growing transcripts, and misleading UI nodes):

```bash
make fixtures
# open http://127.0.0.1:7080/ to list fixture routes
make test-browser
# with fixtures + proxy running, execute the 20x12 acceptance soak:
make test-browser-matrix
# verify typed degradation and browser-session cleanup:
make test-browser-faults
```

The fault matrix covers delayed widgets, stale control shapes, navigation,
rate limits, upstream failures, partial streams, missing assistant responses,
and cancellation. It treats these as explicit degraded/incomplete outcomes,
never as evidence that a target is secure.

### Durable projects and review

Runs, replay manifests, hypotheses, and evidence-backed findings are stored in
SQLite (`GUARDRAIL_DB_PATH`). The default `local` project preserves existing
clients. Findings that are high severity, low confidence, degraded, or disputed
enter a human review queue; only a reviewer can mark them confirmed or rejected.
Cross-lane learning is bounded to the active run and project and uses inert,
semantically varied validation probes instead of copying payloads verbatim.
Credible hypotheses are matched by mechanism or attack family plus target
fingerprint. When run budget remains, GuardRail schedules at most three
one-turn confirmation lanes; quarantined or low-confidence hypotheses cannot
fan out. Blocking attacker and judge calls run through a bounded asynchronous
gateway with explicit timeout/fallback events.

Project retention is configurable and applied explicitly through the API.
JSON exports include the request, coverage, findings, hypotheses, event
timeline, and provenance; SARIF remains available for CI. Before/after reports
are marked comparable only when project, attack corpus, coverage profile,
capture method, and judge versions match.
See [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md) for the authorized testing,
evidence-review, retention, and comparison workflow.

### Judge calibration

GuardRail reconciles deterministic canary, credential, PII, policy-boundary,
scope, and claimed-action evidence with the contextual judge. Strong detector
disagreement is never silently accepted as a pass: it is downgraded to a
pending finding and routed to independent adjudication when configured.
System-prompt wording alone remains informational unless it exposes sensitive
data, enables a bypass, or demonstrates concrete impact.

The versioned local golden set enforces macro-F1 >= 0.85 and confirmed-critical
recall >= 0.95 without making a network request:

```bash
make calibrate-judge
```

### 4) Start full stack

```bash
make up
```

### 5) Open dashboard

- `http://127.0.0.1:3000`

---

## Demo script (for judges)

1. Start with the default vulnerable prompt.
2. Run `High` intensity and show breached lanes.
3. Open Prompt Workbench: show detected weak points.
4. Click `Fix the Prompt` and walk through before/after diff.
5. Click `Apply & Rerun` and highlight improved pass rate.
6. Close with: "same bot, same attacks, lower risk."

---

## API endpoints

- `POST /runs`
- `POST /runs/{id}/start`
- `POST /runs/{id}/cancel`
- `GET /runs/{id}/report`
- `GET /runs/{id}/replay`
- `GET /runs/{id}/export?format=json|sarif`
- `GET /runs/compare?baseline_run_id=...&candidate_run_id=...`
- `POST /browser/preflight`
- `GET|POST /projects`
- `PATCH /projects/{id}`
- `POST /projects/{id}/retention/apply`
- `GET /projects/{id}/findings`
- `GET /projects/{id}/hypotheses`
- `POST /findings/{id}/review`
- `POST /mitigations/generate`
- `POST /mitigations/apply-and-rerun`
- `WS /ws/runs/{id}`

---

## Repo layout

- `backend/` — orchestrator, judge pipeline, mitigation, APIs
- `demo-target/` — intentionally vulnerable chatbot target for demos
- `src/` — frontend console (React + Tailwind)
- `tests/` — unit + integration scaffolds
