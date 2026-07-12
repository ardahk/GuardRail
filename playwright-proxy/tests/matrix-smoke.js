const { modes } = require('../fixtures/server');

const proxy = process.env.GUARDRAIL_FIXTURE_PROXY || 'http://127.0.0.1:7071';
const fixtures = process.env.GUARDRAIL_FIXTURE_BASE || 'http://127.0.0.1:7080';
const repetitions = Number(process.env.GUARDRAIL_MATRIX_REPETITIONS || 20);
const expected = 'Fixture assistant response: I can help with this authorized, inert safety test.';

async function main() {
  let attempts = 0;
  let successes = 0;
  let exact = 0;
  const failures = [];
  for (const mode of modes) {
    for (let i = 0; i < repetitions; i += 1) {
      attempts += 1;
      try {
        const response = await fetch(`${proxy}/preflight`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_url: `${fixtures}/fixture/${mode}`,
            project_id: 'matrix-soak',
            selectors: {},
            safe_probe: true,
            model_fallback: false,
          }),
          signal: AbortSignal.timeout(150000),
        });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(payload.error?.message || `HTTP ${response.status}`);
        successes += 1;
        if (String(payload.probe_response || '').trim() === expected) exact += 1;
        else failures.push({ mode, iteration: i + 1, error: 'response_mismatch' });
      } catch (err) {
        failures.push({ mode, iteration: i + 1, error: String(err.message || err) });
      }
    }
  }
  const successRate = successes / attempts;
  const exactRate = successes ? exact / successes : 0;
  console.log(JSON.stringify({ attempts, successes, exact, successRate, exactRate, failures }, null, 2));
  if (successRate < 0.95 || exactRate < 0.99) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

