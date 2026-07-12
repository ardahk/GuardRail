const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const memoryPath = path.join(os.tmpdir(), `guardrail-selector-test-${process.pid}.json`);
process.env.PLAYWRIGHT_SELECTOR_MEMORY_PATH = memoryPath;

const SelectorMemory = require('../selector-memory');
const { modes, widget } = require('../fixtures/server');

test.after(() => fs.rmSync(memoryPath, { force: true }));

test('fixture matrix includes all twelve browser patterns', () => {
  assert.equal(modes.length, 12);
  for (const expected of [
    'inline-chat', 'launcher-modal', 'same-origin-iframe', 'cross-origin-iframe',
    'shadow-dom', 'contenteditable-input', 'enter-only', 'disabled-send',
    'streamed-text', 'replaced-message-node', 'growing-transcript', 'misleading-nodes',
  ]) assert.ok(modes.includes(expected));
  assert.match(widget('inline-chat'), /authorized, inert safety test/);
});

test('selector profiles are isolated by project and route', () => {
  const memory = new SelectorMemory();
  memory.set('example.test', { input: '#alpha' }, {
    projectId: 'project-a', targetUrl: 'https://example.test/support/12', widgetFingerprint: 'abc', browserVersion: 'test',
  }, { success: true, confidence: 0.9 });
  memory.set('example.test', { input: '#beta' }, {
    projectId: 'project-b', targetUrl: 'https://example.test/help', widgetFingerprint: 'def', browserVersion: 'test',
  }, { success: true, confidence: 0.8 });

  const a = memory.get('example.test', {
    projectId: 'project-a', targetUrl: 'https://example.test/support/99', widgetFingerprint: 'abc', browserVersion: 'test',
  });
  const b = memory.get('example.test', {
    projectId: 'project-b', targetUrl: 'https://example.test/help', widgetFingerprint: 'def', browserVersion: 'test',
  });
  assert.equal(a.input, '#alpha');
  assert.equal(b.input, '#beta');
});

test('invalidating a selector profile lowers confidence', () => {
  const memory = new SelectorMemory();
  const context = { projectId: 'project-c', targetUrl: 'https://invalid.test/chat', widgetFingerprint: 'x', browserVersion: 'test' };
  memory.set('invalid.test', { input: '#chat' }, context, { success: true, confidence: 0.9 });
  assert.equal(memory.invalidate('invalid.test', context), true);
  assert.ok(memory.get('invalid.test', context).confidence < 0.9);
});

