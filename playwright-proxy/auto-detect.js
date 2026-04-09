/**
 * auto-detect.js — resilient selector detection for arbitrary chat widgets.
 *
 * Strategy:
 * - Try main page and all child frames instead of assuming a fixed iframe vendor.
 * - Prefer chat-specific selectors first, then broader fallbacks.
 * - Retry detection after attempting launcher clicks in each context.
 * - Keep bot-message detection lazy (after first send).
 */

const DETECT_TIMEOUT = 3000;
const LAUNCHER_TIMEOUT = 3500;
const CONTEXT_SETTLE_MS = 900;
const LAUNCHER_DISCOVERY_WINDOW_MS = 10000;

const CHAT_HINT_RE = /(chat|support|assistant|help|intercom|drift|crisp|tawk|zendesk|messag|livechat|ask\s*ai|copilot|agent)/i;
const FRAME_BLOCKLIST_RE = /(doubleclick|googleads|googletagmanager|googlesyndication|facebook|analytics|hotjar|segment|newrelic|sentry|optimizely|adservice|nr-data|pixel)/i;

function loc(context, selector) {
  return context.locator(selector);
}

async function hasVisibleChatInput(context) {
  const candidates = [
    'textarea[class*="chat" i]',
    'input[class*="chat" i]',
    '[contenteditable="true"][class*="chat" i]',
    'textarea[aria-label*="ask" i]',
    'textarea[aria-label*="message" i]',
    'textarea[placeholder*="ask" i]',
    'textarea[placeholder*="message" i]',
    'input[placeholder*="message" i]',
  ];
  for (const sel of candidates) {
    try {
      const visible = await firstVisible(context.locator(sel), 700);
      if (visible) return true;
    } catch {
      // try next
    }
  }
  return false;
}

async function firstVisible(locator, timeout = DETECT_TIMEOUT) {
  const count = await locator.count().catch(() => 0);
  for (let i = 0; i < count; i += 1) {
    const nth = locator.nth(i);
    try {
      if (await nth.isVisible({ timeout })) {
        return nth;
      }
    } catch {
      // continue
    }
  }
  return null;
}

async function _clickLauncherInContext(context, customSelector = null) {
  if (customSelector) {
    try {
      const custom = context.locator(customSelector).first();
      if (await custom.isVisible({ timeout: LAUNCHER_TIMEOUT })) {
        await custom.click();
        return customSelector;
      }
    } catch {
      // continue to auto-detect
    }
  }

  const cssStrategies = [
    '[class*="docsbot-launcher"]',
    '[class*="floating-button"]',
    '[class*="chat-widget-button"]',
    '[class*="chat-bubble"]',
    'button[class*="floating-button" i]',
    'button[class*="chatbutton" i]',
    '[id*="launcher" i]',
    '[class*="launcher" i]',
    '[id*="chat-button" i]',
    '[class*="chat-button" i]',
    '[data-testid*="launcher" i]',
    '[data-testid*="chat" i]',
    '[aria-label*="chat" i]',
    '[aria-label*="help" i]',
    '[aria-label*="support" i]',
    'button[title*="chat" i]',
    'a[title*="chat" i]',
  ];

  for (const sel of cssStrategies) {
    try {
      const el = context.locator(sel).first();
      if (await el.isVisible({ timeout: LAUNCHER_TIMEOUT })) {
        await el.click();
        return sel;
      }
    } catch {
      // try next
    }
  }

  const roleStrategies = [
    () => context.getByRole('button', { name: /(chat with us|live chat|ask ai|chat now|message us|talk to support|talk to sales|assistant)/i }),
    () => context.getByRole('link', { name: /(chat with us|live chat|ask ai|chat now|message us|talk to support|talk to sales|assistant)/i }),
  ];

  for (const strategy of roleStrategies) {
    try {
      const el = strategy().first();
      if (await el.isVisible({ timeout: 1500 })) {
        await el.click();
        return '(role-based launcher)';
      }
    } catch {
      // try next
    }
  }

  return null;
}

async function dismissCookieBanners(context) {
  const roleLabels = [
    /accept/i,
    /accept all/i,
    /allow all/i,
    /agree/i,
    /i agree/i,
    /got it/i,
    /continue/i,
  ];

  for (const re of roleLabels) {
    try {
      const btn = context.getByRole('button', { name: re }).first();
      if (await btn.isVisible({ timeout: 400 })) {
        await btn.click().catch(() => {});
        await context.waitForTimeout(250).catch(() => {});
        return true;
      }
    } catch {
      // try next
    }
  }

  const cssButtons = [
    '[id*="cookie" i] button',
    '[class*="cookie" i] button',
    '[id*="consent" i] button',
    '[class*="consent" i] button',
    '[aria-label*="cookie" i] button',
  ];
  for (const sel of cssButtons) {
    try {
      const btn = context.locator(sel).first();
      if (await btn.isVisible({ timeout: 300 })) {
        const text = ((await btn.innerText().catch(() => '')) || '').trim().toLowerCase();
        if (/accept|allow|agree|ok|got it|continue/.test(text)) {
          await btn.click().catch(() => {});
          await context.waitForTimeout(250).catch(() => {});
          return true;
        }
      }
    } catch {
      // try next
    }
  }

  return false;
}

/**
 * Detect and click a launcher on the main page. Best effort.
 *
 * @param {import('playwright').Page} page
 * @param {Object} selectors
 * @returns {Promise<{clicked: boolean, selector: string|null}>}
 */
async function openWidgetLauncher(page, selectors = {}) {
  if (await hasVisibleChatInput(page)) {
    console.log('[AutoDetect] Chat input already visible; skipping launcher click');
    return { clicked: false, selector: null };
  }

  const start = Date.now();
  while (Date.now() - start < LAUNCHER_DISCOVERY_WINDOW_MS) {
    await dismissCookieBanners(page).catch(() => {});

    const clickedSelector = await _clickLauncherInContext(page, selectors.launcher_button || null);
    if (clickedSelector) {
      console.log(`[AutoDetect] Clicked launcher on page: ${clickedSelector}`);
      return { clicked: true, selector: clickedSelector };
    }

    if (await hasVisibleChatInput(page)) {
      console.log('[AutoDetect] Chat input became visible during launcher discovery');
      return { clicked: false, selector: null };
    }
    await page.waitForTimeout(500);
  }

  console.log('[AutoDetect] No launcher found on page; continuing with context scan');
  return { clicked: false, selector: null };
}

async function _frameMeta(page, frame) {
  try {
    const frameEl = await frame.frameElement();
    const attrs = await frameEl.evaluate((el) => ({
      src: el.getAttribute('src') || '',
      title: el.getAttribute('title') || '',
      id: el.getAttribute('id') || '',
      className: el.getAttribute('class') || '',
      name: el.getAttribute('name') || '',
      ariaLabel: el.getAttribute('aria-label') || '',
    }));
    const visible = await frameEl.isVisible().catch(() => false);
    const box = await frameEl.boundingBox().catch(() => null);
    const textBlob = [frame.url(), attrs.src, attrs.title, attrs.id, attrs.className, attrs.name, attrs.ariaLabel].join(' ').toLowerCase();
    const isBlocked = FRAME_BLOCKLIST_RE.test(textBlob);
    const isLargeEnough = !!box && box.width >= 140 && box.height >= 90;

    if (isBlocked) return null;
    if (!visible || !isLargeEnough) return null;

    let score = 20;
    if (CHAT_HINT_RE.test(textBlob)) score += 80;
    if (textBlob.includes('intercom') || textBlob.includes('crisp') || textBlob.includes('tawk') || textBlob.includes('zendesk')) score += 30;

    return {
      context: frame,
      score,
      label: `frame:${attrs.title || attrs.id || attrs.name || frame.url() || 'unknown'}`,
    };
  } catch {
    return null;
  }
}

/**
 * Returns candidate contexts sorted by likelihood (page + frames).
 *
 * @param {import('playwright').Page} page
 * @returns {Promise<Array<{context: import('playwright').Page|import('playwright').Frame, score: number, label: string}>>}
 */
async function getCandidateContexts(page) {
  const candidates = [{ context: page, score: 60, label: 'page:main' }];
  const frames = page.frames().filter((f) => f !== page.mainFrame());

  for (const frame of frames) {
    const meta = await _frameMeta(page, frame);
    if (meta) candidates.push(meta);
  }

  return candidates.sort((a, b) => b.score - a.score);
}

/**
 * Returns most likely frame context for compatibility with legacy callers.
 *
 * @param {import('playwright').Page} page
 * @returns {Promise<import('playwright').Page|import('playwright').Frame>}
 */
async function detectFrame(page) {
  const contexts = await getCandidateContexts(page);
  const best = contexts.find((c) => c.context !== page);
  return best ? best.context : page;
}

/**
 * @param {import('playwright').Page|import('playwright').Frame} context
 * @returns {Promise<{locator: import('playwright').Locator, selector: string|null}>}
 */
async function detectInput(context) {
  const strategies = [
    { selector: 'textarea.docsbot-chat-input', build: () => loc(context, 'textarea.docsbot-chat-input') },
    { selector: 'textarea[class*="chat-input" i]', build: () => loc(context, 'textarea[class*="chat-input" i]') },
    { selector: 'textarea[class*="ai-chat" i]', build: () => loc(context, 'textarea[class*="ai-chat" i]') },
    { selector: 'textarea[class*="message-input" i]', build: () => loc(context, 'textarea[class*="message-input" i]') },
    { selector: 'input[class*="chat-input" i]', build: () => loc(context, 'input[class*="chat-input" i]') },
    { selector: '[data-testid*="chat-input" i]', build: () => loc(context, '[data-testid*="chat-input" i]') },
    { selector: 'textarea[aria-label*="message" i]', build: () => loc(context, 'textarea[aria-label*="message" i]') },
    { selector: 'input[aria-label*="message" i]', build: () => loc(context, 'input[aria-label*="message" i]') },
    { selector: 'textarea[placeholder*="message" i]', build: () => loc(context, 'textarea[placeholder*="message" i]') },
    { selector: 'input[placeholder*="message" i]', build: () => loc(context, 'input[placeholder*="message" i]') },
    { selector: 'textarea[placeholder*="ask" i]', build: () => loc(context, 'textarea[placeholder*="ask" i]') },
    { selector: 'input[placeholder*="ask" i]', build: () => loc(context, 'input[placeholder*="ask" i]') },
    { selector: null, build: () => context.getByPlaceholder(/(message|ask|type|chat|question)/i) },
    { selector: null, build: () => context.getByRole('textbox', { name: /(message|chat|ask|question)/i }) },
    { selector: '[contenteditable="true"][role="textbox"]', build: () => loc(context, '[contenteditable="true"][role="textbox"]') },
    { selector: '[contenteditable="true"][class*="chat" i]', build: () => loc(context, '[contenteditable="true"][class*="chat" i]') },
    { selector: 'textarea', build: () => loc(context, 'textarea') },
  ];

  for (const strategy of strategies) {
    try {
      const target = await firstVisible(strategy.build(), DETECT_TIMEOUT);
      if (!target) continue;
      const disabled = await target.isDisabled().catch(() => false);
      if (disabled) continue;
      return { locator: target, selector: strategy.selector };
    } catch {
      // try next
    }
  }
  throw new Error('Could not auto-detect chat input');
}

/**
 * @param {import('playwright').Page|import('playwright').Frame} context
 * @returns {Promise<{locator: import('playwright').Locator|null, selector: string|null}>}
 */
async function detectSendButton(context) {
  const strategies = [
    { selector: 'button.docsbot-chat-btn-send', build: () => loc(context, 'button.docsbot-chat-btn-send') },
    { selector: 'button[class*="btn-send" i]', build: () => loc(context, 'button[class*="btn-send" i]') },
    { selector: 'button[class*="send-btn" i]', build: () => loc(context, 'button[class*="send-btn" i]') },
    { selector: 'button[aria-label*="send" i]', build: () => loc(context, 'button[aria-label*="send" i]') },
    { selector: 'button[title*="send" i]', build: () => loc(context, 'button[title*="send" i]') },
    { selector: 'button[type="submit"]', build: () => loc(context, 'button[type="submit"]') },
    { selector: '[data-testid*="send" i]', build: () => loc(context, '[data-testid*="send" i]') },
    { selector: null, build: () => context.getByRole('button', { name: /(send|submit|ask|reply)/i }) },
    { selector: null, build: () => loc(context, 'button:has(svg)').last() },
  ];

  for (const strategy of strategies) {
    try {
      const target = await firstVisible(strategy.build(), DETECT_TIMEOUT);
      if (!target) continue;
      // Keep initially-disabled send buttons. Many widgets disable send
      // until text is entered, then enable on input.
      return { locator: target, selector: strategy.selector };
    } catch {
      // try next
    }
  }
  return { locator: null, selector: null };
}

/**
 * Detect bot message containers after first send.
 *
 * @param {import('playwright').Page|import('playwright').Frame} context
 * @returns {Promise<{locator: import('playwright').Locator, selector: string}>}
 */
async function detectBotMessages(context) {
  const strategies = [
    { selector: '[class*="docsbot-chat-bot-message-container"]', build: () => loc(context, '[class*="docsbot-chat-bot-message-container"]') },
    { selector: '[class*="docsbot-chat-bot-message"]', build: () => loc(context, '[class*="docsbot-chat-bot-message"]') },
    { selector: '[data-role="assistant"]', build: () => loc(context, '[data-role="assistant"]') },
    { selector: '[data-message-author-role="assistant"]', build: () => loc(context, '[data-message-author-role="assistant"]') },
    { selector: '[class*="assistant-message" i]', build: () => loc(context, '[class*="assistant-message" i]') },
    { selector: '[class*="bot-message" i]', build: () => loc(context, '[class*="bot-message" i]') },
    { selector: '[class*="ai-message" i]', build: () => loc(context, '[class*="ai-message" i]') },
    { selector: '[class*="response-message" i]', build: () => loc(context, '[class*="response-message" i]') },
    { selector: '[role="log"] [class*="message" i]', build: () => loc(context, '[role="log"] [class*="message" i]') },
    { selector: '[role="log"] p, [role="log"] div, [role="log"] li', build: () => loc(context, '[role="log"] p, [role="log"] div, [role="log"] li') },
    { selector: '[aria-live] [class*="message" i]', build: () => loc(context, '[aria-live] [class*="message" i]') },
    { selector: '[aria-live] p, [aria-live] div, [aria-live] li', build: () => loc(context, '[aria-live] p, [aria-live] div, [aria-live] li') },
    { selector: '[role="log"]', build: () => loc(context, '[role="log"]') },
    { selector: '[aria-live]', build: () => loc(context, '[aria-live]') },
    { selector: '[class*="message" i]:not([class*="user" i]):not([class*="human" i]):not([class*="visitor" i])', build: () => loc(context, '[class*="message" i]:not([class*="user" i]):not([class*="human" i]):not([class*="visitor" i])') },
  ];

  for (const strategy of strategies) {
    try {
      const l = strategy.build();
      if (await l.count() > 0) {
        return { locator: l, selector: strategy.selector };
      }
    } catch {
      // try next
    }
  }
  throw new Error('Could not auto-detect bot message container after first send');
}

async function _resolveInContext(context, selectors = {}, { allowLauncherRetry = false } = {}) {
  let inputInfo = null;

  if (selectors.input) {
    const inputCandidates = loc(context, selectors.input);
    const visible = await firstVisible(inputCandidates, DETECT_TIMEOUT);
    if (visible) {
      inputInfo = { locator: visible, selector: selectors.input };
    }
  } else {
    try {
      inputInfo = await detectInput(context);
    } catch {
      // retry below if allowed
    }
  }

  if (!inputInfo && allowLauncherRetry) {
    await _clickLauncherInContext(context, null);
    await context.waitForTimeout(CONTEXT_SETTLE_MS).catch(() => {});
    if (selectors.input) {
      const inputCandidates = loc(context, selectors.input);
      const visible = await firstVisible(inputCandidates, DETECT_TIMEOUT);
      if (visible) {
        inputInfo = { locator: visible, selector: selectors.input };
      }
    } else {
      inputInfo = await detectInput(context).catch(() => null);
    }
  }

  if (!inputInfo) {
    throw new Error('input not found in this context');
  }

  let sendInfo = { locator: null, selector: null };
  if (selectors.send_button) {
    const sendCandidates = loc(context, selectors.send_button);
    const visible = await firstVisible(sendCandidates, DETECT_TIMEOUT);
    if (!visible) {
      throw new Error(`Custom send_button selector not visible: ${selectors.send_button}`);
    }
    sendInfo = { locator: visible, selector: selectors.send_button };
  } else {
    sendInfo = await detectSendButton(context);
  }

  let botMessages = null;
  if (selectors.bot_message) {
    botMessages = loc(context, selectors.bot_message);
  }

  return {
    input: inputInfo.locator,
    sendButton: sendInfo.locator,
    frame: context,
    resolvedSelectors: {
      launcher_button: selectors.launcher_button || null,
      input: inputInfo.selector || null,
      send_button: sendInfo.selector || null,
      bot_message: selectors.bot_message || null,
    },
    botMessages,
  };
}

/**
 * @param {import('playwright').Page} page
 * @param {Object} selectors
 * @returns {Promise<{input: import('playwright').Locator, sendButton: import('playwright').Locator|null, frame: import('playwright').Page|import('playwright').Frame, botMessages: import('playwright').Locator|null, selectorOverrides: Object, resolvedSelectors: Object}>}
 */
async function buildLocators(page, selectors = {}) {
  const launcher = await openWidgetLauncher(page, selectors);
  await page.waitForTimeout(1200);

  const contexts = await getCandidateContexts(page);
  const errors = [];

  for (const pass of [0, 1]) {
    const allowLauncherRetry = pass === 1;

    for (const candidate of contexts) {
      try {
        const resolved = await _resolveInContext(candidate.context, selectors, { allowLauncherRetry });
        if (!resolved.resolvedSelectors.launcher_button && launcher.selector) {
          resolved.resolvedSelectors.launcher_button = launcher.selector;
        }
        console.log(`[AutoDetect] Resolved chat context: ${candidate.label} (score=${candidate.score})`);
        return {
          ...resolved,
          selectorOverrides: selectors,
        };
      } catch (err) {
        errors.push(`${candidate.label}: ${err.message}`);
      }
    }

    await page.waitForTimeout(CONTEXT_SETTLE_MS);
  }

  const details = errors.slice(0, 8).join(' | ');
  throw new Error(`Could not detect chat input/send on page or iframes. Tried ${contexts.length} contexts. ${details}`);
}

module.exports = {
  openWidgetLauncher,
  detectFrame,
  detectInput,
  detectSendButton,
  detectBotMessages,
  buildLocators,
};
