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

  get(hostname) {
    this._load();
    return this._store[hostname] || null;
  }

  set(hostname, selectors) {
    this._load();
    const clean = {};
    for (const [k, v] of Object.entries(selectors || {})) {
      if (typeof v === 'string' && v.trim()) clean[k] = v.trim();
    }
    if (!Object.keys(clean).length) return;
    this._store[hostname] = {
      ...this._store[hostname],
      ...clean,
      updated_at: new Date().toISOString(),
    };
    this._save();
  }
}

module.exports = SelectorMemory;

