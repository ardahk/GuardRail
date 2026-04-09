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
const SessionManager = require('./session-manager');

const PORT = parseInt(process.env.PLAYWRIGHT_PROXY_PORT || '7071', 10);
const app = express();
app.use(express.json());

const sessions = new SessionManager();

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
      model: 'browser-playwright',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: responseText },
          finish_reason: 'stop',
        },
      ],
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    });
  } catch (err) {
    console.error(`[Proxy] Error in chat: ${err.message}`);
    res.status(502).json({
      error: {
        message: `Playwright proxy error: ${err.message}`,
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
  await sessions.init();
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[Proxy] Playwright proxy listening on http://127.0.0.1:${PORT}`);
  });
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n[Proxy] Shutting down...');
  await sessions.shutdown();
  process.exit(0);
});
process.on('SIGTERM', async () => {
  await sessions.shutdown();
  process.exit(0);
});

start().catch((err) => {
  console.error('[Proxy] Failed to start:', err);
  process.exit(1);
});
