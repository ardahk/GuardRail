/**
 * session-manager.js — Browser context pool keyed by session_id.
 *
 * Each attack lane gets its own fresh BrowserContext (incognito-like).
 * Bot message detection is LAZY: happens after the first message is sent,
 * because there are zero bot messages at session creation time.
 */

const { chromium } = require('playwright');
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

class SessionManager {
  constructor() {
    /** @type {import('playwright').Browser|null} */
    this._browser = null;
    /** @type {Map<string, Session>} */
    this._sessions = new Map();
    this._cleanupTimer = null;
    this._selectorMemory = new SelectorMemory();
  }

  async init() {
    this._browser = await chromium.launch({ headless: true });
    this._cleanupTimer = setInterval(() => this._cleanup(), CLEANUP_INTERVAL_MS);
    console.log('[SessionManager] Browser launched');
  }

  async shutdown() {
    if (this._cleanupTimer) clearInterval(this._cleanupTimer);
    for (const [id, session] of this._sessions) {
      await session.context.close().catch(() => {});
    }
    this._sessions.clear();
    if (this._browser) await this._browser.close();
    console.log('[SessionManager] Shutdown complete');
  }

  get activeCount() {
    return this._sessions.size;
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
      lastResponseText = await this._sendAndWait(session, msg.content);
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
      await page.waitForTimeout(250);
    }
    throw new Error(
      `Chat input stayed disabled/unavailable for ${INPUT_ENABLE_TIMEOUT_MS}ms (widget busy, throttled, or blocked)`,
    );
  }

  async _createSession(sessionId, targetUrl, selectors) {
    if (!this._browser) throw new Error('Browser not initialized');

    console.log(`[SessionManager] Creating session ${sessionId} → ${targetUrl}`);
    const context = await this._browser.newContext({
      viewport: { width: 1280, height: 900 },
    });
    const page = await context.newPage();
    let lastUpstreamError = null;
    page.on('response', async (res) => {
      try {
        const status = res.status();
        if (status < 400) return;
        const req = res.request();
        const method = req.method();
        if (method !== 'POST') return;
        const url = res.url();
        if (!/(assistant|chat|conversation|message|ai|bot)/i.test(url)) return;
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
    const remembered = host ? (this._selectorMemory.get(host) || {}) : {};
    const mergedSelectors = {
      ...remembered,
      ...(selectors || {}),
    };

    // Navigate with tolerant fallbacks.
    // Many production sites keep long-running network connections, so strict
    // `networkidle` as the primary gate creates false startup failures.
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: NAVIGATION_TIMEOUT_MS });
    await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
    await page.waitForTimeout(WIDGET_INIT_WAIT_MS);

    // Open the launcher and detect input/send. Bot messages detected lazily.
    const locators = await buildLocators(page, mergedSelectors);
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
    };
    this._sessions.set(sessionId, session);
    return session;
  }

  async _sendAndWait(session, messageText) {
    const { page, locators } = session;
    const { input, sendButton, frame } = locators;

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

    // Fill the input — try fill() first, fall back to pressSequentially
    try {
      await input.fill(messageText);
      const value = await input.inputValue().catch(() => null);
      if (!value || value.length === 0) throw new Error('fill() did not set value');
    } catch {
      await this._waitForInputReady(input, page, session);
      await input.click({ timeout: 2000 });
      await input.fill('').catch(() => {});
      await input.pressSequentially(messageText, { delay: 20 });
    }

    if (typeof session.clearLastUpstreamError === 'function') {
      session.clearLastUpstreamError();
    }

    // Send
    if (sendButton) {
      try {
        await sendButton.click({ timeout: 4000 });
      } catch {
        await input.press('Enter');
      }
    } else {
      await input.press('Enter');
    }
    // Give async network handlers a moment to observe immediate upstream denials.
    await page.waitForTimeout(1200);
    const immediateUpstreamError = typeof session.getLastUpstreamError === 'function'
      ? session.getLastUpstreamError()
      : null;
    if (immediateUpstreamError) {
      throw new Error(
        `Chat provider rejected automated request (${immediateUpstreamError.status}) at ${immediateUpstreamError.url}`,
      );
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

    const response = await this._waitForResponse(page, locators.botMessages, previousCount, previousLastText);
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
    if (response && session.host) {
      this._selectorMemory.set(session.host, locators.resolvedSelectors || {});
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
        await page.waitForTimeout(500);
      }
    }
    throw new Error('Bot did not respond within timeout (could not detect bot message container)');
  }

  /**
   * Wait for a new bot message to appear and its text to stabilize.
   */
  async _waitForResponse(page, botMessages, previousCount, previousLastText = '') {
    let bestText = '';
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
    // Phase 1: wait for a new bot message element to appear
    const startTime = Date.now();
    while (Date.now() - startTime < NEW_MESSAGE_TIMEOUT_MS) {
      const count = await botMessages.count();
      if (count > previousCount) break;
      await page.waitForTimeout(250);
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
      while (Date.now() - streamStart < NEW_MESSAGE_TIMEOUT_MS) {
        const text = ((await targetMessage.innerText().catch(() => '')) || '').trim();
        if (text.length > bestText.length) bestText = text;
        await captureBestAcrossNodes();
        if (text.length >= MIN_RESPONSE_LENGTH && text !== previousLastText) {
          return text;
        }
        if (bestText.length >= MIN_RESPONSE_LENGTH && bestText !== previousLastText) {
          return bestText;
        }
        await page.waitForTimeout(STABILITY_POLL_MS);
      }
      throw new Error(
        `Bot did not respond within ${NEW_MESSAGE_TIMEOUT_MS}ms (assistant text unchanged; try a more specific bot_message selector)`,
      );
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
      await page.waitForTimeout(STABILITY_POLL_MS);
    }

    // Phase 3: wait for text to stop changing for STABILITY_THRESHOLD_MS
    let previousText = '';
    let stableMs = 0;
    const stabilityStart = Date.now();

    while (stableMs < STABILITY_THRESHOLD_MS && (Date.now() - stabilityStart) < MAX_RESPONSE_WAIT_MS) {
      await page.waitForTimeout(STABILITY_POLL_MS);
      const currentText = (await targetMessage.textContent()) || '';
      if (currentText.trim().length > bestText.length) bestText = currentText.trim();
      await captureBestAcrossNodes();
      if (currentText === previousText && currentText.trim().length >= MIN_RESPONSE_LENGTH) {
        stableMs += STABILITY_POLL_MS;
      } else {
        previousText = currentText;
        stableMs = 0;
      }
    }

    const finalText = (await targetMessage.innerText()) || '';
    const trimmed = finalText.trim();
    if (trimmed.length > 0) return trimmed;
    const crossNode = await captureBestAcrossNodes();
    if (crossNode.length > 0) return crossNode;
    if (bestText.length > 0) return bestText;
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
}

module.exports = SessionManager;
