/** Stable selectors for common chatbot shells. Explicit operator selectors
 * always win; adapters only provide high-confidence defaults. */

const ADAPTERS = [
  {
    name: 'mintlify',
    matches: async (page) => (
      await page.locator('#chat-assistant-textarea, textarea.chat-assistant-input').count().catch(() => 0)
    ) > 0,
    selectors: {
      launcher_button: 'button[aria-label="Toggle assistant panel"]',
      input: '#chat-assistant-textarea',
      send_button: 'button.chat-assistant-send-button',
    },
  },
  {
    name: 'intercom',
    matches: async (page) => (
      await page.locator('iframe[name="intercom-messenger-frame"], .intercom-lightweight-app').count().catch(() => 0)
    ) > 0,
    selectors: {
      launcher_button: '.intercom-lightweight-app-launcher, [aria-label*="Intercom" i]',
    },
  },
  {
    name: 'zendesk',
    matches: async (page) => (
      await page.locator('iframe[title*="Messaging window" i], iframe[id*="launcher" i]').count().catch(() => 0)
    ) > 0,
    selectors: {
      launcher_button: 'button[aria-label*="messaging" i], iframe[title*="Button to launch messaging window" i]',
    },
  },
  {
    name: 'drift',
    matches: async (page) => (
      await page.locator('iframe#drift-widget, iframe[title*="Drift" i]').count().catch(() => 0)
    ) > 0,
    selectors: {
      launcher_button: 'iframe#drift-widget, [aria-label*="chat" i]',
    },
  },
];

async function detectVendorAdapter(page) {
  for (const adapter of ADAPTERS) {
    if (await adapter.matches(page).catch(() => false)) {
      return { name: adapter.name, selectors: { ...adapter.selectors } };
    }
  }
  return { name: 'generic', selectors: {} };
}

module.exports = { ADAPTERS, detectVendorAdapter };
