/**
 * session-manager.js — Browser context pool keyed by session_id.
 *
 * Each attack lane gets its own fresh BrowserContext (incognito-like).
 * Bot message detection is LAZY: happens after the first message is sent,
 * because there are zero bot messages at session creation time.
 */

const fs = require('fs');
const path = require('path');
const { setTimeout: sleep } = require('timers/promises');
const { buildLocators, detectBotMessages } = require('./auto-detect');
const SelectorMemory = require('./selector-memory');

const SESSION_TTL_MS = 5 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 60 * 1000;
const WIDGET_INIT_WAIT_MS = parseInt(process.env.PLAYWRIGHT_WIDGET_INIT_WAIT_MS || '9000', 10);  // wait for JS-injected widgets to load
const STABILITY_THRESHOLD_MS = parseInt(process.env.PLAYWRIGHT_STABILITY_THRESHOLD_MS || '3500', 10); // must be stable for N ms — handles "Searching…" intermediates
const STABILITY_POLL_MS = 300;
const MIN_RESPONSE_LENGTH = 30; // ignore transient loading states shorter than this
const NEW_MESSAGE_TIMEOUT_MS = parseInt(process.env.PLAYWRIGHT_NEW_MESSAGE_TIMEOUT_MS || '90000', 10);
const MAX_RESPONSE_WAIT_MS = parseInt(process.env.PLAYWRIGHT_MAX_RESPONSE_WAIT_MS || '120000', 10);
const NAVIGATION_TIMEOUT_MS = parseInt(process.env.PLAYWRIGHT_NAVIGATION_TIMEOUT_MS || '45000', 10);
const INPUT_ENABLE_TIMEOUT_MS = parseInt(process.env.PLAYWRIGHT_INPUT_ENABLE_TIMEOUT_MS || '20000', 10);
const ACTION_TIMEOUT_MS = parseInt(process.env.PLAYWRIGHT_ACTION_TIMEOUT_MS || '12000', 10);
const APPENDED_MESSAGE_WAIT_MS = parseInt(process.env.PLAYWRIGHT_APPENDED_MESSAGE_WAIT_MS || '3000', 10);
const BROWSER_ENGINE = (process.env.BROWSER_ENGINE || 'cloakbrowser').trim().toLowerCase();
const CLOAKBROWSER_PROFILE_DIR = (process.env.CLOAKBROWSER_PROFILE_DIR || '').trim();
const ARTIFACT_ROOT = path.resolve(process.env.PLAYWRIGHT_ARTIFACT_DIR || '/tmp/guardrail-browser-artifacts');

function envBool(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return /^(1|true|yes|on)$/i.test(raw);
}

const BROWSER_HEADLESS = envBool('CLOAKBROWSER_HEADLESS', true);
const CLOAKBROWSER_HUMANIZE = envBool('CLOAKBROWSER_HUMANIZE', true);
const CAPTURE_SCREENSHOTS = envBool('PLAYWRIGHT_CAPTURE_SCREENSHOTS', false);
const CLOAKBROWSER_HUMAN_PRESET = (process.env.CLOAKBROWSER_HUMAN_PRESET || '').trim();

function sanitizePathSegment(value) {
  return String(value || 'session')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 96) || 'session';
}

function normalizeWhitespace(text) {
  return String(text || '').replace(/\s+/g, ' ').trim();
}

function stripKnownPrefixes(text, previousText = '', userText = '') {
  let out = normalizeWhitespace(text);
  for (const prefix of [previousText, userText, 'Assistant']) {
    const normalizedPrefix = normalizeWhitespace(prefix);
    if (normalizedPrefix && out.toLowerCase().startsWith(normalizedPrefix.toLowerCase())) {
      out = out.slice(normalizedPrefix.length).trim();
    }
  }
  return out;
}

function redactArtifactText(text) {
  return String(text || '')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]')
    .replace(/\b(?:sk-|AKIA)[A-Za-z0-9_-]{12,}\b/g, '[REDACTED_SECRET]')
    .replace(/\b\d{3}[-. ]\d{2,3}[-. ]\d{4}\b/g, '[REDACTED_NUMBER]')
    .slice(0, 2000);
}

async function withTimeout(label, timeoutMs, action) {
  let timer = null;
  try {
    return await Promise.race([
      action(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function firstVisibleEnabled(locator, { allowDisabled = false } = {}) {
  const count = await locator.count().catch(() => 0);
  for (let i = 0; i < count; i += 1) {
    const nth = locator.nth(i);
    const visible = await nth.isVisible().catch(() => false);
    if (!visible) continue;
    const disabled = await nth.isDisabled().catch(() => false);
    if (!allowDisabled && disabled) continue;
    return nth;
  }
  return null;
}

class SessionManager {
  constructor() {
    /** @type {import('playwright-core').Browser|null} */
    this._browser = null;
    /** @type {Map<string, Session>} */
    this._sessions = new Map();
    this._pendingContexts = new Map();
    this._cleanupTimer = null;
    this._selectorMemory = new SelectorMemory();
    this._engine = BROWSER_ENGINE;
    this._cloakbrowser = null;
    this._persistentProfileRoot = CLOAKBROWSER_PROFILE_DIR
      ? path.resolve(CLOAKBROWSER_PROFILE_DIR)
      : null;
  }

  async init() {
    if (this._engine === 'cloakbrowser') {
      if (!process.env.CLOAKBROWSER_AUTO_UPDATE) {
        process.env.CLOAKBROWSER_AUTO_UPDATE = 'false';
      }
      this._cloakbrowser = await import('cloakbrowser');
      if (this._persistentProfileRoot) {
        fs.mkdirSync(this._persistentProfileRoot, { recursive: true });
        console.log(`[SessionManager] CloakBrowser persistent profile root: ${this._persistentProfileRoot}`);
      } else {
        this._browser = await this._cloakbrowser.launch(this._launchOptions());
      }
    } else if (this._engine === 'playwright') {
      const { chromium } = await import('playwright-core');
      this._browser = await chromium.launch({ channel: 'chrome', headless: BROWSER_HEADLESS });
    } else {
      throw new Error(`Unsupported BROWSER_ENGINE "${this._engine}". Use "cloakbrowser" or "playwright".`);
    }
    this._cleanupTimer = setInterval(() => this._cleanup(), CLEANUP_INTERVAL_MS);
    console.log(`[SessionManager] Browser launched (${this._engine})`);
  }

  async shutdown() {
    if (this._cleanupTimer) clearInterval(this._cleanupTimer);
    for (const [id, session] of this._sessions) {
      await session.context.close().catch(() => {});
    }
    for (const context of this._pendingContexts.values()) {
      await context.close().catch(() => {});
    }
    this._sessions.clear();
    this._pendingContexts.clear();
    if (this._browser) await this._browser.close();
    console.log('[SessionManager] Shutdown complete');
  }

  get activeCount() {
    return this._sessions.size + this._pendingContexts.size;
  }

  get modelName() {
    return this._engine === 'cloakbrowser' ? 'browser-cloakbrowser' : 'browser-playwright';
  }

  getDiagnostics(sessionId) {
    const session = this._sessions.get(sessionId);
    return session?.observation || null;
  }

  async preflight(targetUrl, selectors = {}, projectId = 'local', safeProbe = false, modelFallback = false, signal = null) {
    const sessionId = `${projectId}:preflight:${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const cancel = () => this.closeSession(sessionId).catch(() => {});
    signal?.addEventListener('abort', cancel, { once: true });
    try {
      if (signal?.aborted) throw new Error('Browser preflight cancelled');
      let session;
      let modelFallbackResult = { enabled: Boolean(modelFallback), used: false, reason: 'not required' };
      try {
        session = await this._createSession(sessionId, targetUrl, selectors);
      } catch (initialError) {
        await this.closeSession(sessionId);
        if (!modelFallback) throw initialError;
        const hypotheses = await this._discoverSelectorsWithVision(targetUrl);
        session = await this._createSession(sessionId, targetUrl, { ...hypotheses, ...selectors });
        modelFallbackResult = {
          enabled: true,
          used: true,
          reason: 'deterministic discovery was low-confidence or failed; model hypotheses were revalidated',
        };
      }
      let probeResponse = null;
      if (safeProbe) {
        probeResponse = await this._sendAndWait(
          session,
          'Hello. Please briefly describe what this assistant can help with.',
        );
      }
      return {
        ok: true,
        observation: session.observation,
        probe_response: probeResponse,
        selector_overrides: selectors,
        model_fallback: modelFallbackResult,
      };
    } finally {
      signal?.removeEventListener('abort', cancel);
      await this.closeSession(sessionId);
    }
  }

  async _discoverSelectorsWithVision(targetUrl) {
    const apiKey = String(process.env.OPENAI_API_KEY || '').trim();
    if (!apiKey) throw new Error('Model-assisted browser fallback requested but OPENAI_API_KEY is not configured');
    const context = await this._createContext(`vision-${Date.now()}`, targetUrl);
    try {
      const page = context.pages()[0] || await context.newPage();
      await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: NAVIGATION_TIMEOUT_MS });
      await sleep(Math.min(WIDGET_INIT_WAIT_MS, 4000));
      const screenshot = await page.screenshot({ type: 'png', fullPage: false });
      const visibleText = redactArtifactText(await page.locator('body').innerText().catch(() => ''));
      const model = String(process.env.BROWSER_VISION_MODEL || 'gpt-5-mini-2025-08-07');
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          model,
          response_format: { type: 'json_object' },
          messages: [{ role: 'user', content: [
            { type: 'text', text: `Authorized defensive chatbot UI discovery. Return JSON only with optional CSS selectors: launcher_button, input, send_button, bot_message. Use stable id, data-testid, aria-label, role, or short class selectors. Never return coordinates. Visible redacted text:\n${visibleText}` },
            { type: 'image_url', image_url: { url: `data:image/png;base64,${screenshot.toString('base64')}` } },
          ] }],
        }),
        signal: AbortSignal.timeout(30000),
      });
      if (!response.ok) throw new Error(`Browser model fallback failed with status ${response.status}`);
      const payload = await response.json();
      const raw = payload.choices?.[0]?.message?.content || '{}';
      const parsed = JSON.parse(raw);
      const clean = {};
      for (const key of ['launcher_button', 'input', 'send_button', 'bot_message']) {
        if (typeof parsed[key] === 'string' && parsed[key].trim()) clean[key] = parsed[key].trim().slice(0, 300);
      }
      if (!clean.input) throw new Error('Browser model fallback did not identify an input selector');
      return clean;
    } finally {
      await context.close().catch(() => {});
    }
  }

  async _captureObservationArtifact(session) {
    const text = await session.page.locator('body').innerText().catch(() => '');
    session.observation.redacted_dom_excerpt = redactArtifactText(text);
    session.observation.screenshot = { captured: false, reason: 'privacy_default' };
    if (!CAPTURE_SCREENSHOTS) return;
    try {
      fs.mkdirSync(ARTIFACT_ROOT, { recursive: true });
      const filename = `${sanitizePathSegment(session.projectId)}-${Date.now()}.png`;
      const artifactPath = path.join(ARTIFACT_ROOT, filename);
      await session.page.screenshot({ path: artifactPath, fullPage: false });
      session.observation.screenshot = { captured: true, path: artifactPath };
    } catch (err) {
      session.observation.errors.push(`screenshot_failed:${err.message}`);
    }
  }

  async chat(sessionId, messages, targetUrl, selectors = {}) {
    let session = this._sessions.get(sessionId);
    if (!session) {
      session = await this._createSession(sessionId, targetUrl, selectors);
    }
    session.lastActive = Date.now();

    const userMessages = messages.filter((m) => m.role === 'user');
    const newMessages = userMessages.slice(session.sentCount);

    if (newMessages.length === 0) {
      return session.lastResponse || '(no response yet)';
    }

    let lastResponseText = '';
    for (const msg of newMessages) {
      try {
        lastResponseText = await this._sendAndWait(session, msg.content);
      } catch (err) {
        session.observation?.errors?.push(String(err.message || err));
        if (session.host) {
          this._selectorMemory.invalidate(session.host, session.profileContext);
        }
        throw err;
      }
      session.sentCount++;
      session.lastResponse = lastResponseText;
    }
    return lastResponseText;
  }

  async closeSession(sessionId) {
    const session = this._sessions.get(sessionId);
    if (session) {
      await session.context.close().catch(() => {});
      this._sessions.delete(sessionId);
      console.log(`[SessionManager] Closed session ${sessionId}`);
    }
    const pending = this._pendingContexts.get(sessionId);
    if (pending) {
      await pending.close().catch(() => {});
      this._pendingContexts.delete(sessionId);
    }
  }

  async closeAll() {
    const ids = [...this._sessions.keys()];
    for (const id of ids) await this.closeSession(id);
    console.log(`[SessionManager] Closed all sessions (${ids.length})`);
  }

  // ── Internal ───────────────────────────────────────────────────────────

  async _waitForInputReady(input, page, session) {
    const start = Date.now();
    while (Date.now() - start < INPUT_ENABLE_TIMEOUT_MS) {
      const visible = await input.isVisible().catch(() => false);
      const disabled = await input.isDisabled().catch(() => false);
      if (visible && !disabled) return;

      const upstreamError = typeof session.getLastUpstreamError === 'function'
        ? session.getLastUpstreamError()
        : null;
      if (upstreamError) {
        throw new Error(
          `Chat provider rejected automated request (${upstreamError.status}) at ${upstreamError.url}`,
        );
      }
      await sleep(250);
    }
    throw new Error(
      `Chat input stayed disabled/unavailable for ${INPUT_ENABLE_TIMEOUT_MS}ms (widget busy, throttled, or blocked)`,
    );
  }

  async _createSession(sessionId, targetUrl, selectors) {
    if (!this._browser && !(this._engine === 'cloakbrowser' && this._persistentProfileRoot)) {
      throw new Error('Browser not initialized');
    }

    console.log(`[SessionManager] Creating session ${sessionId} → ${targetUrl}`);
    const context = await this._createContext(sessionId, targetUrl);
    this._pendingContexts.set(sessionId, context);
    const page = context.pages()[0] || await context.newPage();
    let lastUpstreamError = null;
    const networkSignals = [];
    page.on('response', async (res) => {
      try {
        const status = res.status();
        const req = res.request();
        const method = req.method();
        if (method !== 'POST') return;
        const url = res.url();
        if (!/(assistant|chat|conversation|message|ai|bot)/i.test(url)) return;
        const contentType = String(res.headers()['content-type'] || '');
        networkSignals.push({
          status,
          content_type: contentType.slice(0, 120),
          url_hint: (() => { try { return new URL(url).pathname.slice(0, 160); } catch { return ''; } })(),
          corroborates_response: status < 400 && /(json|event-stream|text\/plain)/i.test(contentType),
          at: Date.now(),
        });
        if (networkSignals.length > 20) networkSignals.shift();
        if (status < 400) return;
        lastUpstreamError = {
          status,
          url,
          method,
          at: Date.now(),
        };
      } catch {
        // best effort telemetry
      }
    });

    const host = (() => {
      try {
        return new URL(targetUrl).hostname.toLowerCase();
      } catch {
        return '';
      }
    })();
    const projectId = String(sessionId).split(':')[0] || 'local';
    const profileContext = {
      projectId,
      targetUrl,
      browserVersion: this.modelName,
    };
    const remembered = host ? (this._selectorMemory.get(host, profileContext) || {}) : {};
    const mergedSelectors = {
      ...remembered,
      ...(selectors || {}),
    };

    // Navigate with tolerant fallbacks.
    // Many production sites keep long-running network connections, so strict
    // `networkidle` as the primary gate creates false startup failures.
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: NAVIGATION_TIMEOUT_MS });
    await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
    await sleep(WIDGET_INIT_WAIT_MS);

    // Open the launcher and detect input/send. Bot messages detected lazily.
    let locators;
    try {
      locators = await buildLocators(page, mergedSelectors);
    } catch (err) {
      if (Object.keys(remembered).length > 0) {
        console.log(`[SessionManager] Remembered selector profile failed; invalidating and rediscovering: ${err.message}`);
        this._selectorMemory.invalidate(host, profileContext);
        locators = await buildLocators(page, selectors || {});
      } else {
        throw err;
      }
    }
    console.log(`[SessionManager] Session ${sessionId} ready (sendButton: ${locators.sendButton ? 'found' : 'Enter key'})`);

    const session = {
      context,
      page,
      locators,   // { input, sendButton, frame, botMessages: null }
      sentCount: 0,
      lastActive: Date.now(),
      targetUrl,
      host,
      lastResponse: null,
      getLastUpstreamError: () => lastUpstreamError,
      clearLastUpstreamError: () => { lastUpstreamError = null; },
      networkSignals,
      projectId,
      profileContext: {
        ...profileContext,
        widgetFingerprint: locators.diagnostics?.widget_fingerprint || 'unknown',
      },
      observation: {
        schema_version: '1.0',
        project_id: projectId,
        target_url: targetUrl,
        route_pattern: (() => { try { return new URL(targetUrl).pathname || '/'; } catch { return '/'; } })(),
        widget_fingerprint: locators.diagnostics?.widget_fingerprint || '',
        capture_confidence: Number(locators.diagnostics?.confidence || 0),
        selected_controls: locators.resolvedSelectors || {},
        candidates: locators.diagnostics?.candidates || [],
        action_verification: {},
        response_candidates: [],
        timings_ms: {},
        errors: [],
        context_label: locators.diagnostics?.context_label || 'unknown',
      },
    };
    this._sessions.set(sessionId, session);
    this._pendingContexts.delete(sessionId);
    await this._captureObservationArtifact(session);
    return session;
  }

  async _sendAndWait(session, messageText) {
    const { page, locators } = session;
    console.log(`[SessionManager] Sending message in session ${session.host || session.targetUrl} (${messageText.length} chars)`);

    await this._refreshTurnControls(session);
    let { input, sendButton, frame } = locators;

    // Snapshot count before sending (0 if first message)
    const previousCount = locators.botMessages
      ? await locators.botMessages.count()
      : 0;
    const previousLastText = locators.botMessages && previousCount > 0
      ? (((await locators.botMessages.nth(previousCount - 1).innerText().catch(() => '')) || '').trim())
      : '';

    // Some widgets temporarily disable input while generating/streaming.
    // Wait for readiness each turn before attempting interaction.
    await this._waitForInputReady(input, page, session);

    const inputStarted = Date.now();
    await this._setInputText(input, page, session, messageText);
    const actualValue = await input.inputValue().catch(async () => (
      (await input.textContent().catch(() => '')) || ''
    ));
    const inputMatched = normalizeWhitespace(actualValue) === normalizeWhitespace(messageText);
    session.observation.action_verification.input_text_matched = inputMatched;
    session.observation.timings_ms.input = Date.now() - inputStarted;
    if (!inputMatched) {
      session.observation.errors.push('input_text_mismatch');
      throw new Error('Entered text could not be verified before submission');
    }
    await this._refreshTurnControls(session);
    ({ input, sendButton, frame } = locators);
    console.log('[SessionManager] Message text entered');

    if (typeof session.clearLastUpstreamError === 'function') {
      session.clearLastUpstreamError();
    }
    session.networkSignals.length = 0;

    // Send
    if (sendButton) {
      try {
        await withTimeout('send button click', ACTION_TIMEOUT_MS, () => sendButton.click({ timeout: 4000 }));
      } catch {
        await withTimeout('enter key send fallback', ACTION_TIMEOUT_MS, () => input.press('Enter'));
      }
    } else {
      await withTimeout('enter key send', ACTION_TIMEOUT_MS, () => input.press('Enter'));
    }
    console.log('[SessionManager] Message submitted');
    // Give async network handlers a moment to observe immediate upstream denials.
    await sleep(1200);
    const immediateUpstreamError = typeof session.getLastUpstreamError === 'function'
      ? session.getLastUpstreamError()
      : null;
    if (immediateUpstreamError) {
      throw new Error(
        `Chat provider rejected automated request (${immediateUpstreamError.status}) at ${immediateUpstreamError.url}`,
      );
    }
    session.observation.action_verification.network_activity = session.networkSignals.some(
      (item) => item.corroborates_response,
    );
    session.observation.network_signals = session.networkSignals.slice(-8);

    // A remembered bot-message selector may be valid for the controls but
    // stale for this route/widget. Re-detect after submission when it matches
    // no nodes instead of waiting the full response timeout on an empty locator.
    if (locators.botMessages && await locators.botMessages.count().catch(() => 0) === 0) {
      const refreshed = await detectBotMessages(frame).catch(() => null);
      if (refreshed) {
        locators.botMessages = refreshed.locator;
        locators.resolvedSelectors.bot_message = refreshed.selector;
      }
    }

    // Lazy bot message detection: first time we send, detect the container.
    // If user provided bot_message selector, it is prewired in buildLocators.
    if (!locators.botMessages) {
      const detected = await this._waitForFirstBotMessage(page, frame, session);
      locators.botMessages = detected.locator;
      if (!locators.resolvedSelectors.bot_message && detected.selector) {
        locators.resolvedSelectors.bot_message = detected.selector;
      }
    }

    const responseStarted = Date.now();
    const response = await this._waitForResponse(
      page,
      locators.botMessages,
      previousCount,
      previousLastText,
      messageText,
    );
    if (!response || !response.trim()) {
      const upstreamError = typeof session.getLastUpstreamError === 'function'
        ? session.getLastUpstreamError()
        : null;
      if (upstreamError) {
        throw new Error(
          `Chat provider rejected automated request (${upstreamError.status}) at ${upstreamError.url}`,
        );
      }
      throw new Error('No readable chatbot response captured from DOM');
    }
    const normalizedResponse = normalizeWhitespace(response);
    const normalizedUser = normalizeWhitespace(messageText);
    if (normalizedResponse === normalizedUser) {
      session.observation.errors.push('user_echo_rejected');
      throw new Error('Captured text matched the submitted user prompt; assistant response rejected');
    }
    session.observation.action_verification.submission_observed = true;
    session.observation.action_verification.response_distinct_from_user = true;
    session.observation.timings_ms.response = Date.now() - responseStarted;
    session.observation.response_candidates.push({
      text_excerpt: response.slice(0, 240),
      score: 95,
      selected: true,
      distinct_from_user: true,
    });
    session.observation.capture_confidence = Math.min(
      0.99,
      Math.max(Number(session.observation.capture_confidence || 0), 0.9),
    );
    await this._captureObservationArtifact(session);
    if (response && session.host) {
      this._selectorMemory.set(
        session.host,
        locators.resolvedSelectors || {},
        session.profileContext,
        { success: true, confidence: session.observation.capture_confidence },
      );
    }
    return response;
  }

  /**
   * Wait for the very first bot message to appear in the DOM, then return
   * the locator pattern that matched it. Called only once per session.
   *
   * @param {import('playwright').Page} page
   * @param {import('playwright').Page|import('playwright').Frame} frame
   * @param {Session} session
   * @returns {Promise<import('playwright').Locator>}
   */
  async _waitForFirstBotMessage(page, frame, session) {
    console.log('[SessionManager] Waiting for first bot message to detect pattern...');
    const deadline = Date.now() + NEW_MESSAGE_TIMEOUT_MS;

    while (Date.now() < deadline) {
      try {
        const botMessages = await detectBotMessages(frame);
        console.log('[SessionManager] Bot message pattern detected');
        return botMessages;
      } catch {
        // Not yet — keep polling
        const upstreamError = typeof session.getLastUpstreamError === 'function'
          ? session.getLastUpstreamError()
          : null;
        if (upstreamError) {
          throw new Error(
            `Chat provider rejected automated request (${upstreamError.status}) at ${upstreamError.url}`,
          );
        }
        await sleep(500);
      }
    }
    throw new Error('Bot did not respond within timeout (could not detect bot message container)');
  }

  async _setInputText(input, page, session, messageText) {
    try {
      await withTimeout('programmatic input set', ACTION_TIMEOUT_MS, async () => {
        await input.evaluate((el, value) => {
          const element = el;
          const tag = element.tagName.toLowerCase();
          if (tag === 'textarea' || tag === 'input') {
            const proto = tag === 'textarea' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
            const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
            if (setter) setter.call(element, value);
            else element.value = value;
          } else if (element.isContentEditable) {
            element.textContent = value;
          } else {
            element.setAttribute('value', value);
          }
          element.dispatchEvent(new Event('input', { bubbles: true }));
          element.dispatchEvent(new Event('change', { bubbles: true }));
        }, messageText);
      });
      return;
    } catch (err) {
      console.log(`[SessionManager] Programmatic input set failed: ${err.message}; falling back to locator actions`);
    }

    try {
      await withTimeout('input fill', ACTION_TIMEOUT_MS, async () => {
        await input.fill(messageText, { timeout: ACTION_TIMEOUT_MS });
        const value = await input.inputValue().catch(() => null);
        if (!value || value.length === 0) throw new Error('fill() did not set value');
      });
      return;
    } catch (err) {
      console.log(`[SessionManager] input.fill failed: ${err.message}; falling back to keyboard entry`);
    }

    await this._waitForInputReady(input, page, session);
    await withTimeout('keyboard input fallback', ACTION_TIMEOUT_MS * 2, async () => {
      await input.click({ timeout: 2000 });
      await input.fill('').catch(() => {});
      await input.pressSequentially(messageText, { delay: 5, timeout: ACTION_TIMEOUT_MS * 2 });
    });
  }

  async _refreshTurnControls(session) {
    const { locators } = session;
    const frame = locators.frame;
    const resolved = locators.resolvedSelectors || {};

    if (resolved.input) {
      const freshInput = await firstVisibleEnabled(frame.locator(resolved.input));
      if (freshInput) {
        if (freshInput !== locators.input) {
          locators.input = freshInput;
        }
      } else {
        const currentVisible = await locators.input.isVisible().catch(() => false);
        const currentDisabled = await locators.input.isDisabled().catch(() => true);
        console.log(
          `[SessionManager] No fresh visible input for selector ${resolved.input}; current visible=${currentVisible} disabled=${currentDisabled}`,
        );
      }
    }

    if (resolved.send_button) {
      const freshSend = await firstVisibleEnabled(frame.locator(resolved.send_button), { allowDisabled: true });
      if (freshSend) {
        locators.sendButton = freshSend;
      }
    }
  }

  /**
   * Wait for a new bot message to appear and its text to stabilize.
   */
  async _waitForResponse(page, botMessages, previousCount, previousLastText = '', userText = '') {
    let bestText = '';
    const responseStillBusy = async (locator) => locator.evaluate((element) => Boolean(
      element.closest('[aria-busy="true"]')
      || element.ownerDocument.querySelector('[aria-busy="true"], [role="progressbar"]'),
    )).catch(() => false);
    const captureBestAcrossNodes = async () => {
      let longest = bestText;
      const count = await botMessages.count().catch(() => 0);
      for (let i = 0; i < count; i += 1) {
        const text = ((await botMessages.nth(i).innerText().catch(() => '')) || '').trim();
        if (text.length > longest.length) longest = text;
      }
      bestText = longest;
      return longest;
    };
    // Phase 1: briefly wait for widgets that append a fresh assistant node.
    // Some widgets, notably Mintlify's assistant, stream into a stable
    // conversation container remembered from selector memory; those need the
    // text-change fallback below instead of a full response timeout here.
    const startTime = Date.now();
    const appendWaitMs = previousCount > 0 ? APPENDED_MESSAGE_WAIT_MS : NEW_MESSAGE_TIMEOUT_MS;
    while (Date.now() - startTime < appendWaitMs) {
      const count = await botMessages.count();
      if (count > previousCount) break;
      await sleep(250);
    }

    const currentCount = await botMessages.count();
    const hasNewNode = currentCount > previousCount;
    if (!hasNewNode) {
      // Some widgets stream into a single assistant container instead of
      // appending a fresh message node. Fallback to text-change detection.
      if (currentCount === 0) {
        throw new Error(
          `Bot did not respond within ${NEW_MESSAGE_TIMEOUT_MS}ms (no assistant messages detected; set bot_message selector)`,
        );
      }

      const targetMessage = botMessages.last();
      const streamStart = Date.now();
      let previousStableCandidate = '';
      let stableMs = 0;
      while (Date.now() - streamStart < MAX_RESPONSE_WAIT_MS) {
        const text = ((await targetMessage.innerText().catch(() => '')) || '').trim();
        if (text.length > bestText.length) bestText = text;
        await captureBestAcrossNodes();
        const normalizedText = stripKnownPrefixes(text, previousLastText, userText);
        const normalizedBest = stripKnownPrefixes(bestText, previousLastText, userText);
        const candidate = normalizedBest.length > normalizedText.length ? normalizedBest : normalizedText;

        if (candidate.length >= MIN_RESPONSE_LENGTH && candidate === previousStableCandidate) {
          stableMs += STABILITY_POLL_MS;
          if (stableMs >= STABILITY_THRESHOLD_MS && !(await responseStillBusy(targetMessage))) {
            return candidate;
          }
        } else {
          previousStableCandidate = candidate;
          stableMs = 0;
        }

        await sleep(STABILITY_POLL_MS);
      }
      if (await responseStillBusy(targetMessage)) {
        throw new Error(`Bot response remained busy or partially streamed after ${MAX_RESPONSE_WAIT_MS}ms`);
      }
      const normalizedBest = stripKnownPrefixes(bestText, previousLastText, userText);
      if (normalizedBest.length > 0) return normalizedBest;
      throw new Error(`Bot did not produce readable stable text within ${MAX_RESPONSE_WAIT_MS}ms`);
    }

    // Pin to the specific index that just appeared — don't use .last() which
    // shifts when follow-up messages (e.g. "Did that answer your question?") arrive.
    const targetMessage = botMessages.nth(previousCount);

    // Phase 2: wait for non-empty text to appear (bot starts streaming)
    const streamStart = Date.now();
    while (Date.now() - streamStart < NEW_MESSAGE_TIMEOUT_MS) {
      const text = (await targetMessage.textContent()) || '';
      if (text.trim().length > bestText.length) bestText = text.trim();
      await captureBestAcrossNodes();
      if (text.trim().length > 0) break;
      await sleep(STABILITY_POLL_MS);
    }

    // Phase 3: wait for text to stop changing for STABILITY_THRESHOLD_MS
    let previousText = '';
    let stableMs = 0;
    const stabilityStart = Date.now();

    while (stableMs < STABILITY_THRESHOLD_MS && (Date.now() - stabilityStart) < MAX_RESPONSE_WAIT_MS) {
      await sleep(STABILITY_POLL_MS);
      const currentText = (await targetMessage.textContent()) || '';
      if (currentText.trim().length > bestText.length) bestText = currentText.trim();
      await captureBestAcrossNodes();
      const normalizedCurrent = stripKnownPrefixes(currentText, previousLastText, userText);
      if (currentText === previousText && normalizedCurrent.length >= MIN_RESPONSE_LENGTH) {
        stableMs += STABILITY_POLL_MS;
      } else {
        previousText = currentText;
        stableMs = 0;
      }
    }

    const finalText = (await targetMessage.innerText()) || '';
    if (await responseStillBusy(targetMessage)) {
      throw new Error(`Bot response remained busy or partially streamed after ${MAX_RESPONSE_WAIT_MS}ms`);
    }
    const trimmed = stripKnownPrefixes(finalText, previousLastText, userText);
    if (trimmed.length > 0) return trimmed;
    const crossNode = await captureBestAcrossNodes();
    const normalizedCrossNode = stripKnownPrefixes(crossNode, previousLastText, userText);
    if (normalizedCrossNode.length > 0) return normalizedCrossNode;
    const normalizedBestText = stripKnownPrefixes(bestText, previousLastText, userText);
    if (normalizedBestText.length > 0) return normalizedBestText;
    return '';
  }

  _cleanup() {
    const now = Date.now();
    for (const [id, session] of this._sessions) {
      if (now - session.lastActive > SESSION_TTL_MS) {
        session.context.close().catch(() => {});
        this._sessions.delete(id);
        console.log(`[SessionManager] Auto-expired session ${id}`);
      }
    }
  }

  _launchOptions() {
    const options = {
      headless: BROWSER_HEADLESS,
      humanize: CLOAKBROWSER_HUMANIZE,
    };
    if (CLOAKBROWSER_HUMAN_PRESET) {
      options.humanPreset = CLOAKBROWSER_HUMAN_PRESET;
    }
    return options;
  }

  async _createContext(sessionId, targetUrl) {
    if (this._engine === 'cloakbrowser' && this._persistentProfileRoot) {
      const host = (() => {
        try {
          return new URL(targetUrl).hostname;
        } catch {
          return 'target';
        }
      })();
      const userDataDir = path.join(
        this._persistentProfileRoot,
        `${sanitizePathSegment(host)}-${sanitizePathSegment(sessionId)}`,
      );
      fs.mkdirSync(userDataDir, { recursive: true });
      return this._cloakbrowser.launchPersistentContext({
        ...this._launchOptions(),
        userDataDir,
        viewport: { width: 1280, height: 900 },
      });
    }

    if (!this._browser) throw new Error('Browser not initialized');
    return this._browser.newContext({
      viewport: { width: 1280, height: 900 },
    });
  }
}

module.exports = SessionManager;
