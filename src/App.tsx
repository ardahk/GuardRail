import { FormEvent, useState } from 'react';
import ChatWindow from './components/ChatWindow';
import ResultsBar from './components/ResultsBar';
import { useRunSession, defaultSystemPrompt } from './hooks/useRunSession';
import { runtimeConfig } from './api';
import type { Intensity } from './types';

const intensityOptions: { value: Intensity; label: string; desc: string }[] = [
  { value: 'low', label: 'Low', desc: '2–3 attacks' },
  { value: 'medium', label: 'Med', desc: '4–5 attacks' },
  { value: 'high', label: 'High', desc: '6–8 attacks' },
];

const depthOptions: { value: number; label: string; desc: string }[] = [
  { value: 3, label: '3', desc: '3 turns' },
  { value: 4, label: '4', desc: '4 turns' },
  { value: 5, label: '5', desc: '5 turns' },
  { value: 25, label: '∞', desc: 'Keep trying until breach' },
];

function App() {
  const session = useRunSession();

  const [baseUrl, setBaseUrl] = useState('http://127.0.0.1:7070');
  const [apiKey, setApiKey] = useState('demo-key');
  const [model, setModel] = useState('gemini/gemini-2.5-flash-lite');
  const [adminUrl, setAdminUrl] = useState('http://127.0.0.1:7070/admin/system-prompt');
  const [systemPrompt, setSystemPrompt] = useState(defaultSystemPrompt);
  const [intensity, setIntensity] = useState<Intensity>('medium');
  const [maxTurns, setMaxTurns] = useState<number>(3); // default 3 turns
  const [configOpen, setConfigOpen] = useState(false);

  async function handleStart(e: FormEvent) {
    e.preventDefault();
    await session.handleStart({ baseUrl, apiKey, model, adminUrl, systemPrompt, intensity, maxTurns });
  }

  async function handleApplyAndRerun() {
    const result = await session.handleApplyAndRerun(adminUrl.trim() || undefined);
    if (result) {
      setSystemPrompt(result.newSystemPrompt);
    }
  }

  const isRunning = session.status === 'running';
  const hasLanes = session.lanes.length > 0;

  return (
    <div className="flex h-screen flex-col bg-[#06090f] text-slate-100" style={{ fontFamily: "'DM Sans', system-ui, sans-serif" }}>

      {/* ── Header ─────────────────────────────────────────────── */}
      <header className="shrink-0 border-b border-white/5 bg-[#0a0f1a]/95 backdrop-blur-xl">
        <form onSubmit={handleStart}>
          {/* Main row */}
          <div className="mx-auto flex max-w-7xl items-center gap-2.5 px-5 py-3">

            {/* Brand */}
            <div className="flex shrink-0 items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-[#ff6b35] to-[#ff3366] shadow-lg shadow-[#ff6b35]/20">
                <span className="text-sm">🌶️</span>
              </div>
              <div className="leading-none">
                <p className="text-[9px] font-bold uppercase tracking-[0.3em] text-[#ff6b35]">GuardRail</p>
                <p className="text-[13px] font-semibold text-white">Red Team Console</p>
              </div>
            </div>

            <div className="h-8 w-px bg-white/8" />

            {/* Target URL */}
            <div className="flex min-w-0 shrink flex-col gap-0.5">
              <label className="text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-500">Target URL</label>
              <input
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                className="min-w-0 w-36 rounded-lg border border-slate-700/60 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-600 outline-none transition focus:border-[#ff6b35]/50 focus:ring-1 focus:ring-[#ff6b35]/20"
                placeholder="http://127.0.0.1:7070"
              />
            </div>

            {/* Model */}
            <div className="flex min-w-0 shrink flex-col gap-0.5">
              <label className="text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-500">Model</label>
              <input
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="min-w-0 w-32 rounded-lg border border-slate-700/60 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-600 outline-none transition focus:border-[#ff6b35]/50 focus:ring-1 focus:ring-[#ff6b35]/20"
                placeholder="gemini/gemini-2.5-flash-lite"
              />
            </div>

            {/* Intensity */}
            <div className="flex flex-col gap-0.5">
              <label className="text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-500">Intensity</label>
              <div className="flex rounded-lg border border-white/8 bg-white/4 p-0.5">
                {intensityOptions.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setIntensity(opt.value)}
                    title={opt.desc}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition-all ${
                      intensity === opt.value
                        ? 'bg-[#ff6b35] text-white shadow'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Depth */}
            <div className="flex shrink-0 items-center gap-1.5">
              <span className="text-[9px] font-semibold uppercase tracking-[0.18em] text-slate-500">Depth</span>
              <div className="flex rounded-lg border border-slate-700/50 bg-slate-900/60 p-0.5">
                {depthOptions.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    title={opt.desc}
                    onClick={() => setMaxTurns(opt.value === maxTurns ? 0 : opt.value)}
                    className={`rounded-md px-2.5 py-1 text-xs font-semibold transition-all ${
                      maxTurns === opt.value
                        ? 'bg-[#ff6b35] text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Advanced toggle */}
            <button
              type="button"
              onClick={() => setConfigOpen(!configOpen)}
              className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition-all ${
                configOpen
                  ? 'border-[#ff6b35]/40 bg-[#ff6b35]/10 text-[#ff6b35]'
                  : 'border-white/8 bg-white/4 text-slate-400 hover:border-white/15 hover:text-slate-200'
              }`}
            >
              <svg className={`h-3.5 w-3.5 transition-transform ${configOpen ? 'rotate-180' : ''}`} viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 3a1 1 0 01.993.883L9 4v3h3a1 1 0 01.117 1.993L12 9H9v3a1 1 0 01-1.993.117L7 12V9H4a1 1 0 01-.117-1.993L4 7h3V4a1 1 0 011-1z" />
              </svg>
              Advanced
            </button>

            {/* Spacer */}
            <div className="flex-1" />

            {/* WS indicator */}
            <div className="flex items-center gap-2 rounded-lg border border-white/6 bg-white/3 px-3 py-1.5">
              <span className={`h-1.5 w-1.5 rounded-full transition-colors ${session.wsConnected ? 'bg-emerald-400 shadow-[0_0_4px_#34d399]' : 'bg-slate-600'}`} />
              <span className="text-[10px] font-medium text-slate-400">
                {session.wsConnected ? 'Live' : 'Idle'}
              </span>
            </div>

            {/* CTA buttons */}
            <div className="flex items-center gap-2">
              {isRunning && (
                <button
                  type="button"
                  onClick={session.handleCancel}
                  className="flex h-9 items-center gap-1.5 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 text-sm font-medium text-amber-400 transition-all hover:bg-amber-500/20"
                >
                  <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="currentColor">
                    <rect x="4" y="4" width="8" height="8" rx="1" />
                  </svg>
                  Stop
                </button>
              )}
              <button
                type="submit"
                disabled={session.busy}
                className="flex h-9 items-center gap-2 rounded-xl bg-gradient-to-r from-[#ff6b35] to-[#ff3366] px-5 text-sm font-semibold text-white shadow-lg shadow-[#ff6b35]/20 transition-all hover:shadow-[#ff6b35]/40 hover:opacity-90 disabled:opacity-40"
              >
                {session.busy ? (
                  <>
                    <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                      <path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="3" strokeLinecap="round" className="opacity-75" />
                    </svg>
                    Running
                  </>
                ) : (
                  <>
                    <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="currentColor">
                      <path d="M6 4l6 4-6 4V4z" />
                    </svg>
                    Start Attack
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Advanced config panel */}
          {configOpen && (
            <div className="animate-fade-slide-in border-t border-white/5 bg-[#080d17]/60">
              <div className="mx-auto grid max-w-7xl grid-cols-2 gap-3 px-5 py-3 sm:grid-cols-4 items-start">

                <div className="flex flex-col gap-1">
                  <label className="text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-500">API Key</label>
                  <input
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    type="password"
                    className="rounded-lg border border-slate-700/60 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-600 outline-none transition focus:border-[#ff6b35]/50 focus:ring-1 focus:ring-[#ff6b35]/20"
                    placeholder="API key for target"
                  />
                </div>

                <div className="flex flex-col gap-1">
                  <label className="text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-500">Admin URL <span className="normal-case text-slate-600">(for prompt override)</span></label>
                  <input
                    value={adminUrl}
                    onChange={(e) => setAdminUrl(e.target.value)}
                    className="rounded-lg border border-slate-700/60 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-600 outline-none transition focus:border-[#ff6b35]/50 focus:ring-1 focus:ring-[#ff6b35]/20"
                    placeholder="http://...../admin/system-prompt"
                  />
                </div>

                <div className="col-span-2 flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <label className="text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-500">System Prompt Under Test</label>
                    <span className="text-[9px] text-slate-600">{systemPrompt.length} chars · {systemPrompt.split('\n').length} lines</span>
                  </div>
                  <textarea
                    value={systemPrompt}
                    onChange={(e) => setSystemPrompt(e.target.value)}
                    rows={8}
                    className="rounded-lg border border-slate-700/60 bg-slate-900 px-3 py-2 text-[11px] leading-relaxed text-slate-200 placeholder-slate-600 outline-none transition focus:border-[#ff6b35]/50 focus:ring-1 focus:ring-[#ff6b35]/20 font-mono resize-y"
                    placeholder="You are a helpful assistant..."
                  />
                </div>

              </div>
              <div className="mx-auto max-w-7xl border-t border-white/5 px-5 py-2">
                <p className="text-[9px] text-slate-600">
                  Run: <span className="text-slate-500">{session.runId || 'none'}</span>
                  {' · '}API: <span className="text-slate-500">{runtimeConfig.apiBase}</span>
                  {' · '}WS: <span className="text-slate-500">{runtimeConfig.wsBase}</span>
                </p>
              </div>
            </div>
          )}
        </form>
      </header>

      {/* ── Main Chat Grid ──────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto px-4 py-5">
        {!hasLanes ? (
          <EmptyState />
        ) : (
          <div className="mx-auto grid max-w-7xl gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {session.lanes.map((lane, index) => (
              <ChatWindow
                key={lane.laneId}
                laneId={lane.laneId}
                attackId={lane.attackId}
                category={lane.category}
                status={lane.status}
                messages={lane.messages}
                isTyping={lane.isTyping}
                judgeResult={lane.judgeResult}
                index={index}
              />
            ))}
          </div>
        )}
      </main>

      {/* ── Results Bar ─────────────────────────────────────────── */}
      {(hasLanes || session.error) && (
        <ResultsBar
          status={session.status}
          report={session.report}
          lanes={session.lanes}
          mitigation={session.mitigation}
          busy={session.busy}
          error={session.error}
          originalPrompt={systemPrompt}
          onGenerateMitigation={() => session.handleGenerateMitigation(systemPrompt)}
          onApplyAndRerun={handleApplyAndRerun}
        />
      )}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="text-center">
        {/* Decorative ring */}
        <div className="relative mx-auto mb-6 h-24 w-24">
          <div className="absolute inset-0 rounded-full bg-gradient-to-br from-[#ff6b35]/20 to-[#ff3366]/20 blur-xl" />
          <div className="relative flex h-24 w-24 items-center justify-center rounded-full border border-white/8 bg-[#0d1220]">
            <span className="text-4xl">🌶️</span>
          </div>
        </div>
        <h2 className="mb-2 text-lg font-semibold text-slate-200">Ready to Attack</h2>
        <p className="mx-auto max-w-sm text-sm leading-relaxed text-slate-500">
          Configure your target above and hit{' '}
          <span className="font-medium text-[#ff6b35]">Start Attack</span> to launch parallel
          prompt injection attacks. Each attack runs in its own live chat window.
        </p>

        {/* Feature grid */}
        <div className="mt-8 grid grid-cols-3 gap-3 text-left">
          {[
            { icon: '⚡', title: 'Parallel lanes', desc: 'Multiple attacks run simultaneously' },
            { icon: '🤖', title: 'AI-powered', desc: 'Gemini generates adaptive attacks' },
            { icon: '🛡️', title: 'Auto-mitigate', desc: 'Patch your prompt with one click' },
          ].map((f) => (
            <div key={f.title} className="rounded-xl border border-white/6 bg-white/3 p-4">
              <span className="text-2xl">{f.icon}</span>
              <p className="mt-2 text-xs font-semibold text-slate-300">{f.title}</p>
              <p className="mt-0.5 text-[11px] text-slate-500">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default App;
