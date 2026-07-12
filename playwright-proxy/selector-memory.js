const fs = require('fs');
const path = require('path');

const STORE_PATH = process.env.PLAYWRIGHT_SELECTOR_MEMORY_PATH || path.join('/tmp', 'guardrail-selector-memory.json');

class SelectorMemory {
  constructor() {
    this._store = {};
    this._loaded = false;
  }

  _load() {
    if (this._loaded) return;
    this._loaded = true;
    try {
      if (fs.existsSync(STORE_PATH)) {
        this._store = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8')) || {};
      }
    } catch {
      this._store = {};
    }
  }

  _save() {
    try {
      fs.writeFileSync(STORE_PATH, JSON.stringify(this._store, null, 2), 'utf8');
    } catch {
      // best-effort persistence only
    }
  }

  _key(hostname, context = {}) {
    const projectId = String(context.projectId || 'local').replace(/[^a-zA-Z0-9._-]/g, '_');
    let route = '/';
    try {
      const url = new URL(context.targetUrl || `https://${hostname}/`);
      route = url.pathname.replace(/[0-9a-f]{8,}|\d+/ig, ':id').replace(/\/$/, '') || '/';
    } catch {}
    const fingerprint = String(context.widgetFingerprint || 'unknown').slice(0, 40);
    const browserVersion = String(context.browserVersion || 'unknown').slice(0, 40);
    return `${projectId}|${hostname}|${route}|${fingerprint}|${browserVersion}`;
  }

  get(hostname, context = {}) {
    this._load();
    const exact = this._store[this._key(hostname, context)];
    if (exact) return exact;
    // Backward-compatible host-only profile and same-project/origin fallback.
    if (this._store[hostname]) return this._store[hostname];
    const prefix = `${String(context.projectId || 'local')}|${hostname}|`;
    const candidates = Object.entries(this._store)
      .filter(([key]) => key.startsWith(prefix))
      .map(([, value]) => value)
      .sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0));
    return candidates[0] || null;
  }

  set(hostname, selectors, context = {}, outcome = {}) {
    this._load();
    const clean = {};
    for (const [k, v] of Object.entries(selectors || {})) {
      if (typeof v === 'string' && v.trim()) clean[k] = v.trim();
    }
    if (!Object.keys(clean).length) return;
    const key = this._key(hostname, context);
    const previous = this._store[key] || {};
    this._store[key] = {
      ...previous,
      ...clean,
      project_id: context.projectId || 'local',
      origin: hostname,
      route_pattern: key.split('|')[2],
      widget_fingerprint: context.widgetFingerprint || 'unknown',
      browser_version: context.browserVersion || 'unknown',
      confidence: Number(outcome.confidence ?? previous.confidence ?? 0.5),
      successes: Number(previous.successes || 0) + (outcome.success ? 1 : 0),
      failures: Number(previous.failures || 0) + (outcome.failure ? 1 : 0),
      updated_at: new Date().toISOString(),
    };
    this._save();
  }

  invalidate(hostname, context = {}) {
    this._load();
    const key = this._key(hostname, context);
    if (!this._store[key]) return false;
    this._store[key].confidence = Math.max(0, Number(this._store[key].confidence || 0.5) - 0.25);
    this._store[key].failures = Number(this._store[key].failures || 0) + 1;
    this._store[key].updated_at = new Date().toISOString();
    this._save();
    return true;
  }
}

module.exports = SelectorMemory;
