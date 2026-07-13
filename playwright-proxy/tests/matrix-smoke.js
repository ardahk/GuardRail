const { modes } = require('../fixtures/server');

const proxy = process.env.GUARDRAIL_FIXTURE_PROXY || 'http://127.0.0.1:7071';
const fixtures = process.env.GUARDRAIL_FIXTURE_BASE || 'http://127.0.0.1:7080';
const repetitions = Number(process.env.GUARDRAIL_MATRIX_REPETITIONS || 20);
const selectedModes = String(process.env.GUARDRAIL_MATRIX_MODES || '').trim()
  ? String(process.env.GUARDRAIL_MATRIX_MODES).split(',').map((item) => item.trim()).filter(Boolean)
  : modes;
const expected = 'Fixture assistant response: I can help with this authorized, inert safety test.';

async function main() {
  let attempts = 0;
  let successes = 0;
  let exact = 0;
  const failures = [];
  const perPattern = {};
  for (const mode of selectedModes) {
    perPattern[mode] = { attempts: 0, successes: 0, exact: 0, latencies_ms: [], failures: [] };
    for (let i = 0; i < repetitions; i += 1) {
      attempts += 1;
      perPattern[mode].attempts += 1;
      const started = Date.now();
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
        perPattern[mode].successes += 1;
        perPattern[mode].latencies_ms.push(Date.now() - started);
        if (String(payload.probe_response || '').trim() === expected) {
          exact += 1;
          perPattern[mode].exact += 1;
        } else {
          const failure = { mode, iteration: i + 1, error: 'response_mismatch' };
          failures.push(failure); perPattern[mode].failures.push(failure);
        }
      } catch (err) {
        const failure = { mode, iteration: i + 1, error: String(err.message || err) };
        failures.push(failure); perPattern[mode].failures.push(failure);
      }
    }
  }
  const successRate = successes / attempts;
  const exactRate = successes ? exact / successes : 0;
  const percentile = (values, pct) => {
    if (!values.length) return null;
    const ordered = [...values].sort((a, b) => a - b);
    return ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * pct) - 1)];
  };
  for (const stats of Object.values(perPattern)) {
    stats.success_rate = stats.successes / stats.attempts;
    stats.exact_rate = stats.successes ? stats.exact / stats.successes : 0;
    stats.latency_p50_ms = percentile(stats.latencies_ms, 0.5);
    stats.latency_p95_ms = percentile(stats.latencies_ms, 0.95);
    delete stats.latencies_ms;
  }
  let health = null;
  try { health = await (await fetch(`${proxy}/health`)).json(); } catch {}
  const sessionLeak = Number(health?.active_sessions || 0) !== 0;
  console.log(JSON.stringify({
    schema_version: '1.0', generated_at: new Date().toISOString(), attempts, successes,
    exact, successRate, exactRate, sessionLeak, runtime: health, perPattern, failures,
  }, null, 2));
  if (successRate < 0.95 || exactRate < 0.99 || sessionLeak) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
