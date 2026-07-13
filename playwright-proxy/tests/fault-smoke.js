const { faultModes } = require('../fixtures/server');

const proxy = process.env.GUARDRAIL_FIXTURE_PROXY || 'http://127.0.0.1:7071';
const fixtures = process.env.GUARDRAIL_FIXTURE_BASE || 'http://127.0.0.1:7080';
const expected = 'Fixture assistant response: I can help with this authorized, inert safety test.';

const expectations = {
  'delayed-widget': { ok: true, response: expected },
  'stale-selector-shape': { ok: true, response: expected },
  navigation: { ok: true, response: expected },
  'rate-limit': { ok: false, code: 'upstream_rejected' },
  'upstream-error': { ok: false, code: 'upstream_rejected' },
  'partial-stream': { ok: false, code: 'response_capture_failed' },
  'missing-assistant': { ok: false, code: 'response_capture_failed' },
};

async function preflight(mode, signal = AbortSignal.timeout(30000)) {
  const response = await fetch(`${proxy}/preflight`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target_url: `${fixtures}/fault/${mode}`,
      project_id: 'fault-smoke',
      selectors: {},
      safe_probe: true,
      model_fallback: false,
    }),
    signal,
  });
  return { status: response.status, payload: await response.json() };
}

async function waitForNoSessions() {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const health = await (await fetch(`${proxy}/health`)).json();
    if (Number(health.active_sessions) === 0) return health;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('browser sessions leaked after fault probes');
}

async function main() {
  const results = [];
  for (const mode of faultModes) {
    const expectation = expectations[mode];
    const started = Date.now();
    const { status, payload } = await preflight(mode);
    const actualOk = status < 400 && payload.ok === true;
    const actualResponse = String(payload.probe_response || '').trim();
    const actualCode = payload.error?.code || null;
    const passed = expectation.ok
      ? actualOk && actualResponse === expectation.response
      : !actualOk && actualCode === expectation.code;
    results.push({ mode, passed, status, code: actualCode, response: actualResponse, latency_ms: Date.now() - started });
  }

  const controller = new AbortController();
  const cancellation = preflight('missing-assistant', controller.signal).catch((error) => ({ aborted: error.name === 'AbortError' }));
  setTimeout(() => controller.abort(), 250);
  const cancellationResult = await cancellation;
  const health = await waitForNoSessions();
  const cancellationPassed = cancellationResult.aborted === true && Number(health.active_sessions) === 0;
  results.push({ mode: 'cancellation', passed: cancellationPassed, active_sessions: health.active_sessions });

  console.log(JSON.stringify({ schema_version: '1.0', results }, null, 2));
  if (results.some((result) => !result.passed)) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
