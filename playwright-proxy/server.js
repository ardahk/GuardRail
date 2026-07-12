/**
 * server.js — Playwright proxy for GuardRail.
 *
 * Exposes an OpenAI-compatible /v1/chat/completions endpoint that
 * automates a real website's chat widget via Playwright. The GuardRail
 * backend sends requests here exactly as it would to any API target.
 *
 * Endpoints:
 *   POST   /v1/chat/completions  — Send message, get bot response
 *   DELETE /sessions/:id         — Close a specific session
 *   DELETE /sessions             — Close all sessions
 *   GET    /health               — Health check
 */

const express = require('express');
const http = require('http');
const SessionManager = require('./session-manager');

const PORT = parseInt(process.env.PLAYWRIGHT_PROXY_PORT || '7071', 10);
const app = express();
app.use(express.json());

const sessions = new SessionManager();
let server = null;

function classifyProxyError(err) {
  const message = String(err?.message || err || 'Unknown browser automation failure');
  let code = 'browser_action_failed';
  if (/response|assistant messages|stable text|user prompt/i.test(message)) code = 'response_capture_failed';
  else if (/auto-detect|detect chat|input not found|selector/i.test(message)) code = 'control_discovery_failed';
  else if (/rejected automated request|\(4\d\d\)|\(5\d\d\)/i.test(message)) code = 'upstream_rejected';
  else if (/timeout|timed out/i.test(message)) code = 'browser_timeout';
  return { code, message, retryable: ['browser_timeout', 'control_discovery_failed'].includes(code) };
}

app.post('/preflight', async (req, res) => {
  const { target_url, selectors, project_id, safe_probe, model_fallback } = req.body || {};
  if (!target_url) return res.status(400).json({ error: { code: 'invalid_request', message: 'target_url is required' } });
  try {
    const result = await sessions.preflight(
      target_url,
      selectors || {},
      project_id || 'local',
      Boolean(safe_probe),
      Boolean(model_fallback),
    );
    if (!result.model_fallback) result.model_fallback = { enabled: Boolean(model_fallback), used: false, reason: 'disabled' };
    res.json(result);
  } catch (err) {
    const error = classifyProxyError(err);
    res.status(502).json({ error });
  }
});

// ── POST /v1/chat/completions ──────────────────────────────

app.post('/v1/chat/completions', async (req, res) => {
  const { messages, session_id, target_url, selectors } = req.body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages array is required' });
  }
  if (!session_id) {
    return res.status(400).json({ error: 'session_id is required' });
  }
  if (!target_url) {
    return res.status(400).json({ error: 'target_url is required' });
  }

  try {
    const responseText = await sessions.chat(
      session_id,
      messages,
      target_url,
      selectors || {},
    );

    const ts = Math.floor(Date.now() / 1000);
    res.json({
      id: `chatcmpl-pw-${ts}`,
      object: 'chat.completion',
      created: ts,
      model: sessions.modelName,
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: responseText },
          finish_reason: 'stop',
        },
      ],
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      guardrail: sessions.getDiagnostics(session_id),
    });
  } catch (err) {
    console.error(`[Proxy] Error in chat: ${err.message}`);
    const typed = classifyProxyError(err);
    res.status(502).json({
      error: {
        ...typed,
        message: `Browser proxy error: ${typed.message}`,
        type: 'proxy_error',
      },
    });
  }
});

// ── DELETE /sessions/:id ───────────────────────────────────

app.delete('/sessions/:id', async (req, res) => {
  await sessions.closeSession(req.params.id);
  res.json({ ok: true });
});

// ── DELETE /sessions ───────────────────────────────────────

app.delete('/sessions', async (req, res) => {
  await sessions.closeAll();
  res.json({ ok: true });
});

// ── GET /health ────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ ok: true, active_sessions: sessions.activeCount });
});

// ── Start ──────────────────────────────────────────────────

async function start() {
  server = http.createServer(app);
  await new Promise((resolve, reject) => {
    const onError = (err) => {
      server.off('listening', onListening);
      reject(err);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };

    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(PORT, '127.0.0.1');
  });

  await sessions.init();
  console.log(`[Proxy] Playwright proxy listening on http://127.0.0.1:${PORT}`);
}

async function shutdown(exitCode = 0) {
  console.log('\n[Proxy] Shutting down...');
  if (server) {
    await new Promise((resolve) => server.close(() => resolve()));
  }
  await sessions.shutdown();
  process.exit(exitCode);
}

// Graceful shutdown
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

start().catch((err) => {
  if (err && err.code === 'EADDRINUSE') {
    console.error(`[Proxy] Failed to start: 127.0.0.1:${PORT} is already in use.`);
  } else {
    console.error('[Proxy] Failed to start:', err);
  }
  process.exit(1);
});
