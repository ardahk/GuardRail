import { FormEvent, useEffect, useState } from 'react';
import ChatWindow from './components/ChatWindow';
import ResultsBar from './components/ResultsBar';
import { useRunSession, defaultSystemPrompt } from './hooks/useRunSession';
import { clearDirectorMemory, getDirectorMemory, runtimeConfig } from './api';
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
];

const allAttackCategories = ['scope_bypass', 'persona_hijack', 'prompt_leak', 'data_exfil', 'multi_turn'];
const burritoDemoTarget = 'http://127.0.0.1:7070';

function App() {
  const session = useRunSession();

  const [runMode, setRunMode] = useState<'website' | 'burrito_demo'>('website');
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [playwrightSelectors, setPlaywrightSelectors] = useState<Record<string, string>>({});
  const [showSelectors, setShowSelectors] = useState(false);
  const [showSelectorGuide, setShowSelectorGuide] = useState(false);
  const [websiteContextHint, setWebsiteContextHint] = useState('');
  const [attackCategories, setAttackCategories] = useState<string[]>(allAttackCategories);
  const [intensity, setIntensity] = useState<Intensity>('medium');
  const [maxTurns, setMaxTurns] = useState<number>(3);
  const [customDepthMode, setCustomDepthMode] = useState(false);
  const [customDepth, setCustomDepth] = useState('6');
  const [configOpen, setConfigOpen] = useState(false);
  const [memoryBusy, setMemoryBusy] = useState(false);
  const [memoryMessage, setMemoryMessage] = useState('');
  const [memoryPreview, setMemoryPreview] = useState<{
    confidence: number;
    successCount: number;
    failCount: number;
    lastSeen: string;
  } | null>(null);

  const isWebsiteMode = runMode === 'website';
  const effectiveTargetType: 'api' | 'browser' = isWebsiteMode ? 'browser' : 'api';

  function normalizeSelectorInput(raw: string): string {
    const value = raw.trim();
    if (!value) return '';
    if (value.startsWith('.') || value.startsWith('#') || value.startsWith('[') || value.includes('>') || value.includes(':')) {
      return value;
    }
    const idMatch = value.match(/^id\s*=\s*["']?([^"']+)["']?$/i);
    if (idMatch) return `#${idMatch[1]}`;
    const attrMatch = value.match(/^([a-zA-Z_-][\w-]*)\s*=\s*["']?([^"']+)["']?$/);
    if (attrMatch) return `[${attrMatch[1]}="${attrMatch[2]}"]`;
    return value;
  }

  function updatePlaywrightSelector(field: 'launcher_button' | 'input' | 'send_button' | 'bot_message', raw: string) {
    const normalized = normalizeSelectorInput(raw);
    setPlaywrightSelectors((prev) => {
      const next = { ...prev };
      if (normalized) next[field] = normalized;
      else delete next[field];
      return next;
    });
  }

  function currentDomain(): string {
    if (!websiteUrl.trim()) return '';
    try {
      return new URL(websiteUrl.trim()).hostname.toLowerCase();
    } catch {
      return '';
    }
  }

  async function handleLoadMemory() {
    const domain = currentDomain();
    if (!domain) {
      setMemoryMessage('Enter a valid website URL first.');
      return;
    }
    setMemoryBusy(true);
    setMemoryMessage('');
    try {
      const res = await getDirectorMemory(domain);
      if (!res.memory) {
        setMemoryPreview(null);
        setMemoryMessage(`No saved memory for ${domain}.`);
        return;
      }
      setMemoryPreview({
        confidence: Number(res.memory.confidence ?? 0),
        successCount: Array.isArray(res.memory.successful_patterns) ? res.memory.successful_patterns.length : 0,
        failCount: Array.isArray(res.memory.failed_patterns) ? res.memory.failed_patterns.length : 0,
        lastSeen: String(res.memory.last_seen ?? ''),
      });
      setMemoryMessage(`Loaded memory for ${domain}.`);
    } catch (err) {
      setMemoryMessage((err as Error).message);
    } finally {
      setMemoryBusy(false);
    }
  }

  async function handleClearMemory() {
    const domain = currentDomain();
    if (!domain) {
      setMemoryMessage('Enter a valid website URL first.');
      return;
    }
    setMemoryBusy(true);
    setMemoryMessage('');
    try {
      const res = await clearDirectorMemory(domain);
      setMemoryPreview(null);
      setMemoryMessage(res.cleared ? `Cleared memory for ${domain}.` : `No memory existed for ${domain}.`);
    } catch (err) {
      setMemoryMessage((err as Error).message);
    } finally {
      setMemoryBusy(false);
    }
  }

  async function handleStart(e: FormEvent) {
    e.preventDefault();
    const parsedCustom = Number(customDepth);
    const effectiveTurns = customDepthMode
      ? Math.max(1, Number.isFinite(parsedCustom) ? Math.floor(parsedCustom) : 6)
      : maxTurns;

    if (isWebsiteMode && !websiteUrl.trim()) {
      return;
    }

    await session.handleStart({
      baseUrl: isWebsiteMode ? 'http://127.0.0.1:7071' : burritoDemoTarget,
      apiKey: 'demo-key',
      model: isWebsiteMode ? 'browser' : 'burritobot-vuln-1',
      adminUrl: isWebsiteMode ? '' : `${burritoDemoTarget}/admin/system-prompt`,
      systemPrompt: isWebsiteMode ? websiteContextHint : defaultSystemPrompt,
      intensity,
      maxTurns: effectiveTurns,
      targetType: effectiveTargetType,
      playwrightTargetUrl: isWebsiteMode ? websiteUrl : '',
      playwrightSelectors,
      attackCategories,
    });
  }

  useEffect(() => {
    if (
      effectiveTargetType === 'browser' &&
      session.status === 'failed' &&
      !!session.error &&
      /selector|chatbot|valid response|warmup|launcher/i.test(session.error)
    ) {
      setShowSelectorGuide(true);
    }
  }, [effectiveTargetType, session.status, session.error]);

  async function handleApplyAndRerun() {
    const result = await session.handleApplyAndRerun(
      runMode === 'burrito_demo' ? `${burritoDemoTarget}/admin/system-prompt` : undefined
    );
    if (result) {
      if (runMode === 'website') {
        setWebsiteContextHint(result.newSystemPrompt);
      }
    }
  }

  const isRunning = session.status === 'running';
  const hasLanes = session.lanes.length > 0;

  return (
    <div className="relative flex h-screen flex-col overflow-hidden bg-[#070b12] text-slate-100" style={{ fontFamily: "'Sora', 'DM Sans', system-ui, sans-serif" }}>
      <div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_20%_10%,rgba(249,115,22,0.14),transparent_32%),radial-gradient(circle_at_82%_12%,rgba(34,197,94,0.1),transparent_30%),linear-gradient(180deg,#070b12,#05080f_42%,#03060c)]" />
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-44 bg-[linear-gradient(90deg,rgba(249,115,22,0.11),rgba(16,185,129,0.08),rgba(249,115,22,0.11))] blur-2xl animate-aurora-shift" />

      <header className="shrink-0 border-b border-white/10 bg-[#0b111d]/80 backdrop-blur-xl">
        <form onSubmit={handleStart}>
          <div className="mx-auto flex w-full max-w-7xl flex-col gap-3 px-4 py-4 lg:px-6">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex min-w-0 items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#fb923c]/45 bg-gradient-to-br from-[#fb923c]/30 to-[#f97316]/10 shadow-[0_10px_24px_rgba(249,115,22,0.25)] animate-float-slow">
                  <span className="text-base">🌯</span>
                </div>
                <div className="min-w-0">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.25em] text-[#fdba74]">GuardRail</p>
                  <p className="truncate text-sm font-semibold text-white">Red Team Command Deck</p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setRunMode('website')}
                  className={`rounded-xl border px-3 py-1.5 text-xs font-semibold transition-all ${
                    runMode === 'website'
                      ? 'border-cyan-300/40 bg-cyan-300/15 text-cyan-100 shadow-[0_0_0_1px_rgba(103,232,249,0.18)]'
                      : 'border-white/12 bg-white/5 text-slate-300 hover:border-white/20 hover:text-slate-100'
                  }`}
                >
                  Website URL
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRunMode('burrito_demo');
                    setConfigOpen(false);
                  }}
                  className={`rounded-xl border px-3 py-1.5 text-xs font-semibold transition-all ${
                    runMode === 'burrito_demo'
                      ? 'border-[#fb923c]/50 bg-[#fb923c]/20 text-[#fed7aa] shadow-[0_0_0_1px_rgba(251,146,60,0.25)]'
                      : 'border-white/12 bg-white/5 text-slate-300 hover:border-white/20 hover:text-slate-100'
                  }`}
                >
                  Burrito Bot Demo
                </button>
              </div>

              <div className="ml-auto flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-1.5">
                <span className={`h-2 w-2 rounded-full ${session.wsConnected ? 'bg-emerald-400 shadow-[0_0_6px_#34d399]' : 'bg-slate-500'}`} />
                <span className="text-[11px] font-medium text-slate-300">{session.wsConnected ? 'Live stream' : 'Waiting'}</span>
              </div>
            </div>

            <div className="flex flex-wrap items-end gap-2.5">
              {isWebsiteMode ? (
                <div className="min-w-[260px] flex-1">
                  <label className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-200/75">Website URL</label>
                  <input
                    value={websiteUrl}
                    onChange={(e) => setWebsiteUrl(e.target.value)}
                    className="h-10 w-full rounded-xl border border-cyan-300/25 bg-slate-950/70 px-3 text-sm text-slate-100 placeholder-slate-500 outline-none transition focus:border-cyan-200/45 focus:ring-2 focus:ring-cyan-300/20"
                    placeholder="https://your-chatbot-site.com"
                  />
                </div>
              ) : (
                <div className="min-w-[260px] flex-1 rounded-xl border border-[#fb923c]/30 bg-[#fb923c]/10 px-3 py-2.5">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[#fdba74]">Demo Target</p>
                  <p className="mt-0.5 text-sm font-medium text-[#ffedd5]">Burrito Bot Vulnerable Profile</p>
                  <p className="mt-0.5 text-[11px] text-[#fed7aa]/90">Runs against local demo target at {burritoDemoTarget}</p>
                </div>
              )}

              <div className="flex items-center gap-1 rounded-xl border border-white/10 bg-white/5 p-1">
                {intensityOptions.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setIntensity(opt.value)}
                    title={opt.desc}
                    className={`rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all ${
                      intensity === opt.value
                        ? 'bg-[#f97316] text-white'
                        : 'text-slate-300 hover:bg-white/10 hover:text-slate-100'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1 rounded-xl border border-white/10 bg-white/5 p-1">
                {depthOptions.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    title={opt.desc}
                    onClick={() => {
                      setCustomDepthMode(false);
                      setMaxTurns(opt.value);
                    }}
                    className={`rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all ${
                      !customDepthMode && maxTurns === opt.value
                        ? 'bg-emerald-500/80 text-emerald-50'
                        : 'text-slate-300 hover:bg-white/10 hover:text-slate-100'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
                <button
                  type="button"
                  onClick={() => setCustomDepthMode((v) => !v)}
                  className={`rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-all ${
                    customDepthMode ? 'bg-emerald-500/80 text-emerald-50' : 'text-slate-300 hover:bg-white/10 hover:text-slate-100'
                  }`}
                >
                  Custom
                </button>
                {customDepthMode && (
                  <input
                    type="number"
                    min={1}
                    step={1}
                    value={customDepth}
                    onChange={(e) => setCustomDepth(e.target.value)}
                    className="h-8 w-16 rounded-md border border-emerald-300/35 bg-slate-900 px-2 text-xs text-slate-100 outline-none focus:border-emerald-300/60"
                  />
                )}
              </div>

              <button
                type="button"
                onClick={() => setConfigOpen((v) => !v)}
                className={`h-10 rounded-xl border px-3 text-xs font-semibold transition-all ${
                  configOpen
                    ? 'border-cyan-300/35 bg-cyan-300/10 text-cyan-100'
                    : 'border-white/15 bg-white/5 text-slate-300 hover:border-white/25 hover:text-slate-100'
                }`}
              >
                {configOpen ? 'Hide Advanced' : 'Advanced'}
              </button>

              <div className="ml-auto flex items-center gap-2">
                {effectiveTargetType === 'browser' && <RunStagePill stage={session.runStage} />}
                {isRunning && (
                  <button
                    type="button"
                    onClick={session.handleCancel}
                    className="flex h-10 items-center gap-1.5 rounded-xl border border-amber-500/45 bg-amber-500/10 px-4 text-sm font-medium text-amber-200 transition hover:bg-amber-500/20"
                  >
                    <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="currentColor">
                      <rect x="4" y="4" width="8" height="8" rx="1" />
                    </svg>
                    Stop
                  </button>
                )}
                <button
                  type="submit"
                  disabled={session.busy || (isWebsiteMode && !websiteUrl.trim())}
                  className="flex h-10 items-center gap-2 rounded-xl bg-gradient-to-r from-[#f97316] via-[#fb923c] to-[#fb7185] px-5 text-sm font-semibold text-white shadow-[0_10px_24px_rgba(249,115,22,0.3)] transition-all duration-200 hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-45"
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
                      Launch Attack
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {configOpen && (
            <div className="animate-fade-slide-in border-t border-white/10 bg-[#090f1a]/80">
              <div className="mx-auto grid max-w-7xl grid-cols-1 gap-3 px-4 py-3 lg:grid-cols-2 lg:px-6">
                {isWebsiteMode ? (
                  <div className="flex flex-col gap-2 rounded-xl border border-cyan-300/20 bg-cyan-300/5 p-3">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-200/80">Website Capture Tuning</p>
                    <button
                      type="button"
                      onClick={() => setShowSelectors(!showSelectors)}
                      className="w-fit rounded-lg border border-cyan-300/30 bg-cyan-300/10 px-2.5 py-1 text-[11px] font-semibold text-cyan-100"
                    >
                      {showSelectors ? 'Hide custom selectors' : 'Show custom selectors'}
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowSelectorGuide((v) => !v)}
                      className="w-fit rounded-lg border border-white/20 bg-white/5 px-2.5 py-1 text-[11px] font-semibold text-slate-200"
                    >
                      {showSelectorGuide ? 'Hide selector guide' : 'How to find selectors'}
                    </button>
                    {showSelectors && (
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                        {(['launcher_button', 'input', 'send_button', 'bot_message'] as const).map((field) => (
                          <div key={field} className="flex flex-col gap-1">
                            <label className="text-[9px] font-semibold uppercase tracking-[0.15em] text-cyan-200/75">
                              {field.replace('_', ' ')}
                            </label>
                            <input
                              value={playwrightSelectors[field] || ''}
                              onChange={(e) => updatePlaywrightSelector(field, e.target.value)}
                              className="rounded-lg border border-cyan-300/25 bg-slate-950/70 px-2.5 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-500 outline-none transition focus:border-cyan-200/50 focus:ring-1 focus:ring-cyan-300/25"
                              placeholder="CSS selector"
                            />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="rounded-xl border border-[#fb923c]/25 bg-[#fb923c]/8 p-3 text-xs text-[#ffedd5]">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[#fdba74]">Demo Mode</p>
                    <p className="mt-1">Uses the bundled Burrito Bot target so you can showcase breached lanes and prompt hardening quickly.</p>
                    <p className="mt-2 text-[11px] text-[#fed7aa]/85">Make sure `demo-target` is running before launching the attack.</p>
                  </div>
                )}

                <div className="flex flex-col gap-2 rounded-xl border border-white/12 bg-white/5 p-3">
                  <label className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                    {isWebsiteMode ? 'Website Context Hint (Optional)' : 'Demo Prompt Under Test'}
                  </label>
                  <textarea
                    value={isWebsiteMode ? websiteContextHint : defaultSystemPrompt}
                    onChange={(e) => {
                      if (isWebsiteMode) setWebsiteContextHint(e.target.value);
                    }}
                    rows={isWebsiteMode ? 4 : 8}
                    readOnly={!isWebsiteMode}
                    className={`rounded-lg border bg-slate-950/70 px-3 py-2 text-[11px] leading-relaxed outline-none transition font-mono resize-y ${
                      isWebsiteMode
                        ? 'border-white/15 text-slate-200 placeholder-slate-500 focus:border-cyan-300/45 focus:ring-1 focus:ring-cyan-300/20'
                        : 'border-[#fb923c]/35 text-[#fed7aa]'
                    }`}
                    placeholder="Optional context helps the judge score responses more accurately."
                  />
                  {isWebsiteMode ? (
                    <p className="text-[10px] text-slate-500">For third-party bots, this hint improves verdict quality without requiring direct prompt access.</p>
                  ) : (
                    <p className="text-[10px] text-[#fdba74]/80">This known vulnerable prompt powers mitigation generation and apply-and-rerun in demo mode.</p>
                  )}
                </div>

                <div className="lg:col-span-2 flex flex-col gap-2 rounded-xl border border-white/12 bg-white/5 p-3">
                  <label className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">Attack Categories</label>
                  <div className="flex flex-wrap gap-1.5">
                    {allAttackCategories.map((cat) => {
                      const selected = attackCategories.includes(cat);
                      return (
                        <button
                          key={cat}
                          type="button"
                          onClick={() =>
                            setAttackCategories((prev) =>
                              prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
                            )
                          }
                          className={`rounded-md border px-2 py-1 text-[10px] ${
                            selected
                              ? 'border-[#f97316]/50 bg-[#f97316]/12 text-[#fdba74]'
                              : 'border-slate-700/60 bg-slate-950 text-slate-400'
                          }`}
                        >
                          {cat}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>
              <div className="mx-auto max-w-7xl border-t border-white/10 px-4 py-2 lg:px-6">
                <p className="text-[10px] text-slate-500">
                  Run: <span className="text-slate-400">{session.runId || 'none'}</span>
                  {' · '}API: <span className="text-slate-400">{runtimeConfig.apiBase}</span>
                  {' · '}WS: <span className="text-slate-400">{runtimeConfig.wsBase}</span>
                </p>
              </div>
            </div>
          )}
        </form>
      </header>

      <main className="flex-1 overflow-y-auto px-4 py-5 lg:px-6">
        {effectiveTargetType === 'browser' && (
          <div className="mx-auto mb-4 grid max-w-7xl gap-3 sm:grid-cols-2">
            <div className="rounded-xl border border-cyan-300/20 bg-cyan-300/8 p-3 text-xs text-slate-300">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-cyan-200">Run Stage</p>
              <p className="mt-1 text-sm text-slate-100">{formatStage(session.runStage)}</p>
              <p className="mt-1 text-[11px] text-slate-400">Analyzing target {'->'} Planning attacks {'->'} Running lanes</p>
              {session.error && (
                <p className="mt-2 rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-[11px] text-red-300">
                  {session.error}
                </p>
              )}
              <div className="mt-3 grid grid-cols-4 gap-2 text-[10px]">
                <StageChip label="Analyze" active={session.runStage === 'analyzing'} done={['planning', 'connecting', 'running_lanes', 'completed'].includes(session.runStage)} />
                <StageChip label="Plan" active={session.runStage === 'planning'} done={['connecting', 'running_lanes', 'completed'].includes(session.runStage)} />
                <StageChip label="Connect" active={session.runStage === 'connecting'} done={['running_lanes', 'completed'].includes(session.runStage)} />
                <StageChip label="Parallel" active={session.runStage === 'running_lanes'} done={session.runStage === 'completed'} />
              </div>
            </div>
            <DirectorPanel
              decision={session.directorPanel.lastDecision}
              recentDecisions={session.directorPanel.recentDecisions}
              rebalance={session.directorPanel.rebalance}
              memory={session.directorPanel.memory}
              memoryPreview={memoryPreview}
              memoryBusy={memoryBusy}
              memoryMessage={memoryMessage}
              onLoadMemory={handleLoadMemory}
              onClearMemory={handleClearMemory}
            />
          </div>
        )}
        {!hasLanes ? (
          <EmptyState runMode={runMode} />
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
                laneBadges={lane.laneBadges}
                mutation={lane.mutation}
                strategyReason={lane.strategyReason}
              />
            ))}
          </div>
        )}
      </main>

      {(hasLanes || session.error) && (
        <ResultsBar
          status={session.status}
          targetType={effectiveTargetType}
          report={session.report}
          lanes={session.lanes}
          mitigation={session.mitigation}
          busy={session.busy}
          error={session.error}
          originalPrompt={runMode === 'burrito_demo' ? defaultSystemPrompt : websiteContextHint}
          onGenerateMitigation={() => session.handleGenerateMitigation(defaultSystemPrompt)}
          onApplyAndRerun={handleApplyAndRerun}
        />
      )}

      {showSelectorGuide && isWebsiteMode && (
        <SelectorGuideModal
          onClose={() => setShowSelectorGuide(false)}
          selectors={playwrightSelectors}
          onChangeSelector={updatePlaywrightSelector}
        />
      )}
    </div>
  );
}

function EmptyState({ runMode }: { runMode: 'website' | 'burrito_demo' }) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="w-full max-w-2xl text-center">
        <div className="relative mx-auto mb-6 h-24 w-24">
          <div className="absolute inset-0 rounded-full bg-gradient-to-br from-[#f97316]/30 to-[#14b8a6]/20 blur-xl" />
          <div className="relative flex h-24 w-24 items-center justify-center rounded-full border border-white/12 bg-[#0d1322]">
            <span className="text-4xl">🌯</span>
          </div>
        </div>
        <h2 className="mb-2 text-lg font-semibold text-slate-200">Ready to Red Team</h2>
        <p className="mx-auto max-w-md text-sm leading-relaxed text-slate-400">
          {runMode === 'website'
            ? 'Enter a chatbot website URL and launch parallel attacks to identify risky responses in real time.'
            : 'Launch the Burrito Bot demo to showcase GuardRail breach detection and auto-hardening end to end.'}
        </p>

        <div className="mt-8 grid gap-3 text-left sm:grid-cols-3">
          {[
            { icon: '⚡', title: 'Parallel lanes', desc: 'Multiple adversarial prompts at once' },
            { icon: '🧠', title: 'Smart scoring', desc: 'Judge severity, confidence, and flags live' },
            { icon: '🛡️', title: 'Auto hardening', desc: 'Generate and rerun prompt mitigations fast' },
          ].map((f) => (
            <div key={f.title} className="rounded-xl border border-white/10 bg-white/5 p-4 backdrop-blur-sm animate-fade-slide-in">
              <span className="text-2xl">{f.icon}</span>
              <p className="mt-2 text-xs font-semibold text-slate-200">{f.title}</p>
              <p className="mt-0.5 text-[11px] text-slate-400">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default App;

function StageChip({ label, active, done }: { label: string; active: boolean; done: boolean }) {
  return (
    <span
      className={`rounded-md border px-2 py-1 text-center font-semibold ${
        active
          ? 'border-cyan-300/65 bg-cyan-300/20 text-cyan-100'
          : done
          ? 'border-emerald-500/45 bg-emerald-500/15 text-emerald-200'
          : 'border-white/10 bg-white/5 text-slate-500'
      }`}
    >
      {label}
    </span>
  );
}

function formatStage(stage: string): string {
  if (stage === 'analyzing') return 'Analyzing target';
  if (stage === 'planning') return 'Planning attacks';
  if (stage === 'running_lanes') return 'Running lanes';
  if (stage === 'completed') return 'Completed';
  if (stage === 'failed') return 'Failed';
  return 'Idle';
}

function RunStagePill({ stage }: { stage: string }) {
  const label = formatStage(stage);
  return (
    <div className="rounded-lg border border-cyan-300/35 bg-cyan-300/10 px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-cyan-100">
      {label}
    </div>
  );
}

function DirectorPanel({
  decision,
  recentDecisions,
  rebalance,
  memory,
  memoryPreview,
  memoryBusy,
  memoryMessage,
  onLoadMemory,
  onClearMemory,
}: {
  decision?: { laneId?: string; action: string; reason: string; decisionSource: string };
  recentDecisions?: Array<{ laneId?: string; action: string; reason: string; decisionSource: string; tacticHint?: string; ts?: string }>;
  rebalance?: { message: string; focusCategory?: string; decisionSource?: string };
  memory?: { domain: string; confidence: number };
  memoryPreview?: { confidence: number; successCount: number; failCount: number; lastSeen: string } | null;
  memoryBusy: boolean;
  memoryMessage: string;
  onLoadMemory: () => void;
  onClearMemory: () => void;
}) {
  return (
    <div className="rounded-xl border border-white/12 bg-[#0a101c] p-3 text-xs text-slate-300">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Director Panel</p>
      <p className="mt-1 text-slate-200">
        {decision ? `${decision.action} (${decision.decisionSource})` : 'No decision yet'}
      </p>
      <p className="mt-1 text-[11px] text-slate-400">{decision?.reason || 'Waiting for lane feedback...'}</p>
      {!!recentDecisions?.length && (
        <div className="mt-2 max-h-28 space-y-1 overflow-auto rounded-lg border border-white/10 bg-[#0d1220] p-2">
          {recentDecisions.slice().reverse().map((item, idx) => (
            <p key={`${item.ts || 't'}-${idx}`} className="text-[10px] text-slate-300">
              [{item.laneId || 'run'}] {item.action} · {item.reason}
            </p>
          ))}
        </div>
      )}
      {rebalance && (
        <p className="mt-2 text-[11px] text-slate-400">
          Rebalance: {rebalance.focusCategory || 'n/a'} · {rebalance.decisionSource || 'fallback'}
        </p>
      )}
      {memory && (
        <p className="mt-2 text-[11px] text-emerald-300">
          Using learned strategy for {memory.domain} ({Math.round(memory.confidence * 100)}%)
        </p>
      )}
      <div className="mt-3 border-t border-white/10 pt-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Director Memory</p>
        <div className="mt-2 flex items-center gap-2">
          <button
            type="button"
            onClick={onLoadMemory}
            disabled={memoryBusy}
            className="rounded-lg border border-slate-600/60 bg-slate-800 px-2 py-1 text-[10px] font-semibold text-slate-200 disabled:opacity-50"
          >
            {memoryBusy ? 'Loading...' : 'Load'}
          </button>
          <button
            type="button"
            onClick={onClearMemory}
            disabled={memoryBusy}
            className="rounded-lg border border-red-500/40 bg-red-500/10 px-2 py-1 text-[10px] font-semibold text-red-300 disabled:opacity-50"
          >
            Clear
          </button>
        </div>
        {memoryPreview && (
          <p className="mt-2 text-[11px] text-slate-400">
            Confidence {Math.round(memoryPreview.confidence * 100)}% · Success patterns {memoryPreview.successCount} · Failed patterns {memoryPreview.failCount}
          </p>
        )}
        {memoryPreview?.lastSeen && (
          <p className="mt-1 text-[10px] text-slate-500">Last seen: {new Date(memoryPreview.lastSeen).toLocaleString()}</p>
        )}
        {memoryMessage && <p className="mt-1 text-[10px] text-slate-500">{memoryMessage}</p>}
      </div>
    </div>
  );
}

function SelectorGuideModal({
  onClose,
  selectors,
  onChangeSelector,
}: {
  onClose: () => void;
  selectors: Record<string, string>;
  onChangeSelector: (field: 'launcher_button' | 'input' | 'send_button' | 'bot_message', raw: string) => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#01040a]/75 p-4">
      <div className="w-full max-w-2xl rounded-2xl border border-cyan-300/30 bg-[#0b1220] p-4 text-slate-200 shadow-2xl">
        <div className="mb-3 flex items-center justify-between">
          <p className="text-sm font-semibold text-cyan-200">Selector Setup Guide</p>
          <button onClick={onClose} className="rounded-md border border-white/15 px-2 py-1 text-xs text-slate-300">Close</button>
        </div>
        <p className="text-xs text-slate-300">
          Use CSS selectors only. Paste raw selector text (no backticks). Quotes are needed inside attribute selectors.
        </p>
        <div className="mt-3 space-y-2 text-xs">
          <p><span className="font-semibold text-slate-100">launcher_button</span>: button that opens chat panel.</p>
          <code className="block rounded bg-[#111827] px-2 py-1 text-cyan-200">button[aria-label="Toggle assistant panel"]</code>
          <p><span className="font-semibold text-slate-100">input</span>: chat text box.</p>
          <code className="block rounded bg-[#111827] px-2 py-1 text-cyan-200">textarea[placeholder*="Ask a question"]</code>
          <p><span className="font-semibold text-slate-100">send_button</span>: submit/send button.</p>
          <code className="block rounded bg-[#111827] px-2 py-1 text-cyan-200">button[aria-label*="send" i]</code>
          <p><span className="font-semibold text-slate-100">bot_message</span>: assistant message bubble/container.</p>
          <code className="block rounded bg-[#111827] px-2 py-1 text-cyan-200">[data-message-author-role="assistant"]</code>
        </div>
        <p className="mt-3 text-[11px] text-slate-400">
          Tip: avoid long copied chains. Prefer id / data-testid / aria-label selectors because they are more stable.
        </p>
        <div className="mt-4 grid grid-cols-2 gap-2">
          {(['launcher_button', 'input', 'send_button', 'bot_message'] as const).map((field) => (
            <div key={field} className="flex flex-col gap-1">
              <label className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">{field.replace('_', ' ')}</label>
              <input
                value={selectors[field] || ''}
                onChange={(e) => onChangeSelector(field, e.target.value)}
                placeholder="CSS selector"
                className="rounded-md border border-cyan-300/30 bg-[#0f172a] px-2 py-1 text-xs text-slate-100 outline-none focus:border-cyan-300/60"
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
