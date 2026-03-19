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
- `POST /mitigations/generate`
- `POST /mitigations/apply-and-rerun`
- `WS /ws/runs/{id}`

---

## Repo layout

- `backend/` — orchestrator, judge pipeline, mitigation, APIs
- `demo-target/` — intentionally vulnerable chatbot target for demos
- `src/` — frontend console (React + Tailwind)
- `tests/` — unit + integration scaffolds
