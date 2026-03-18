import type { LaneView, MitigationResponse, RunReport, RunStatus } from '../types';

interface ResultsBarProps {
  status: RunStatus;
  report: RunReport | null;
  lanes: LaneView[];
  mitigation: MitigationResponse | null;
  busy: boolean;
  error: string | null;
  originalPrompt: string;
  onGenerateMitigation: () => void;
  onApplyAndRerun: () => void;
}

function DiffView({ original, patched }: { original: string; patched: string }) {
  const origLines = original.split('\n');
  const patchLines = patched.split('\n');
  const maxLines = Math.max(origLines.length, patchLines.length);

  return (
    <div className="grid grid-cols-2 gap-4 text-xs">
      <div>
        <p className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
          <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
          Original
        </p>
        <div className="max-h-44 overflow-auto rounded-xl border border-white/6 bg-[#06090f] p-3 font-mono leading-relaxed">
          {origLines.map((line, i) => (
            <div
              key={i}
              className={`px-1 py-px ${
                i < maxLines && patchLines[i] !== line
                  ? 'rounded bg-red-500/10 text-red-300/80'
                  : 'text-slate-400'
              }`}
            >
              {line || '\u00A0'}
            </div>
          ))}
        </div>
      </div>
      <div>
        <p className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          Patched
        </p>
        <div className="max-h-44 overflow-auto rounded-xl border border-white/6 bg-[#06090f] p-3 font-mono leading-relaxed">
          {patchLines.map((line, i) => (
            <div
              key={i}
              className={`px-1 py-px ${
                i >= origLines.length || origLines[i] !== line
                  ? 'rounded bg-emerald-500/10 text-emerald-300/80'
                  : 'text-slate-400'
              }`}
            >
              {line || '\u00A0'}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function ResultsBar({
  status,
  report,
  lanes,
  mitigation,
  busy,
  error,
  originalPrompt,
  onGenerateMitigation,
  onApplyAndRerun,
}: ResultsBarProps) {
  const total = lanes.length;
  const breached = lanes.filter((l) => l.status === 'breached').length;
  const secure = lanes.filter((l) => l.status === 'secure').length;
  const done = lanes.filter((l) => ['breached', 'secure', 'error'].includes(l.status)).length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  const isRunning = status === 'running';
  const hasLaneResults = report !== null && (report.lanes?.length ?? 0) > 0;
  const isDone = (status === 'completed' || status === 'failed') && hasLaneResults;
  const showPromptWorkbench = isDone || mitigation !== null;

  const successRate = report ? Math.round(report.success_rate * 100) : null;
  const criticalFailures = report ? report.total_critical_failures : null;
  const detectedIssues = lanes
    .filter((lane) => lane.status === 'breached' && lane.judgeResult)
    .sort((a, b) => (b.judgeResult?.severity ?? 0) - (a.judgeResult?.severity ?? 0));

  return (
    <div className="shrink-0 border-t border-white/5 bg-[#0a0f1a]/95 backdrop-blur-xl">

      {/* ── Progress bar (during run) ───────────────────────── */}
      {isRunning && total > 0 && (
        <div className="relative h-0.5 w-full overflow-hidden bg-white/5">
          <div
            className="h-full bg-gradient-to-r from-[#ff6b35] to-[#ff3366] transition-all duration-700 ease-out"
            style={{ width: `${pct}%` }}
          />
        </div>
      )}

      {/* ── Main bar ───────────────────────────────────────── */}
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-5 py-3">

        {/* KPI stats */}
        <div className="flex items-center gap-3">

          {/* Breached */}
          {total > 0 && (
            <div className="flex items-center gap-2 rounded-xl border border-red-500/20 bg-red-500/8 px-4 py-2">
              <div>
                <p className="text-[9px] font-semibold uppercase tracking-[0.2em] text-red-400/70">Breached</p>
                <p className="text-xl font-bold leading-tight text-red-400">
                  {breached}
                  <span className="ml-1 text-sm font-normal text-red-400/50">/ {total}</span>
                </p>
              </div>
            </div>
          )}

          {/* Secure */}
          {total > 0 && (
            <div className="flex items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/8 px-4 py-2">
              <div>
                <p className="text-[9px] font-semibold uppercase tracking-[0.2em] text-emerald-400/70">Secure</p>
                <p className="text-xl font-bold leading-tight text-emerald-400">
                  {secure}
                  <span className="ml-1 text-sm font-normal text-emerald-400/50">/ {total}</span>
                </p>
              </div>
            </div>
          )}

          {/* Attack success rate */}
          {successRate !== null && (
            <div className="flex items-center gap-2 rounded-xl border border-white/8 bg-white/4 px-4 py-2">
              <div>
                <p className="text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-500">Attack rate</p>
                <p className={`text-xl font-bold leading-tight ${successRate > 50 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {successRate}%
                </p>
              </div>
            </div>
          )}

          {/* Critical failures */}
          {criticalFailures !== null && criticalFailures > 0 && (
            <div className="flex items-center gap-2 rounded-xl border border-orange-500/20 bg-orange-500/8 px-4 py-2">
              <div>
                <p className="text-[9px] font-semibold uppercase tracking-[0.2em] text-orange-400/70">Critical</p>
                <p className="text-xl font-bold leading-tight text-orange-400">{criticalFailures}</p>
              </div>
            </div>
          )}

          {/* Live progress during run */}
          {isRunning && total > 0 && (
            <p className="text-xs text-slate-500">
              <span className="font-semibold text-slate-300">{done}</span> / {total} complete
            </p>
          )}
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Error */}
        {error && (
          <div className="flex max-w-xs items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-1.5">
            <svg className="h-3.5 w-3.5 shrink-0 text-red-400" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 1a7 7 0 100 14A7 7 0 008 1zm-.75 3.75a.75.75 0 011.5 0v3.5a.75.75 0 01-1.5 0v-3.5zm.75 7a.875.875 0 110-1.75.875.875 0 010 1.75z" />
            </svg>
            <span className="truncate text-xs text-red-300">{error}</span>
          </div>
        )}

        {/* Action area intentionally left for layout balance */}
        <div className="flex items-center gap-2" />
      </div>

      {/* ── Prompt workbench ─────────────────────────────────── */}
      {showPromptWorkbench && (
        <div className="animate-fade-slide-in border-t border-white/5 bg-[#080d17]/60 px-5 pb-5 pt-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Prompt Workbench</p>
            <div className="flex items-center gap-2">
              {isDone && !mitigation && (
                <button
                  onClick={onGenerateMitigation}
                  disabled={busy}
                  className="flex h-9 items-center gap-1.5 rounded-xl border border-[#ff6b35]/40 bg-[#ff6b35]/10 px-4 text-sm font-semibold text-[#ff6b35] transition-all hover:bg-[#ff6b35]/20 disabled:opacity-40"
                >
                  {busy ? (
                    <>
                      <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                        <path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="3" strokeLinecap="round" className="opacity-75" />
                      </svg>
                      Generating...
                    </>
                  ) : (
                    <>
                      <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M8 1a.75.75 0 01.75.75v4.5h4.5a.75.75 0 010 1.5h-4.5v4.5a.75.75 0 01-1.5 0v-4.5H2.75a.75.75 0 010-1.5h4.5V1.75A.75.75 0 018 1z" />
                      </svg>
                      Fix the Prompt
                    </>
                  )}
                </button>
              )}
              {mitigation && (
                <button
                  onClick={onApplyAndRerun}
                  disabled={busy}
                  className="flex h-9 items-center gap-1.5 rounded-xl bg-gradient-to-r from-[#ff6b35] to-[#ff3366] px-5 text-sm font-semibold text-white shadow-lg shadow-[#ff6b35]/20 transition-all hover:opacity-90 disabled:opacity-40"
                >
                  {busy ? (
                    <>
                      <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                        <path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="3" strokeLinecap="round" className="opacity-75" />
                      </svg>
                      Applying...
                    </>
                  ) : (
                    <>
                      <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M14 8A6 6 0 112 8a6 6 0 0112 0zm-3.25-2.25a.75.75 0 00-1.06-1.06L7 7.44l-1.19-1.19a.75.75 0 00-1.06 1.06l1.75 1.75a.75.75 0 001.06 0l3.19-3.19z" />
                      </svg>
                      Apply & Rerun
                    </>
                  )}
                </button>
              )}
            </div>
          </div>

          {mitigation ? (
            <DiffView original={originalPrompt} patched={mitigation.patched_system_prompt} />
          ) : (
            <div className="text-xs">
              <p className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                Current Prompt
              </p>
              <div className="max-h-44 overflow-auto rounded-xl border border-white/6 bg-[#06090f] p-3 font-mono leading-relaxed text-slate-400">
                {originalPrompt}
              </div>
            </div>
          )}

          {mitigation && mitigation.changes_made.length > 0 && (
            <div className="mt-4 grid gap-3 xl:grid-cols-2">
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-3">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-red-300">Detected Weak Points</p>
                {detectedIssues.length > 0 ? (
                  <div className="space-y-2">
                    {detectedIssues.map((issue) => (
                      <div key={issue.laneId} className="rounded-lg border border-red-500/15 bg-[#090e19] px-2.5 py-2">
                        <div className="mb-1 flex items-center justify-between gap-2 text-[11px]">
                          <span className="rounded bg-red-500/15 px-1.5 py-0.5 font-semibold uppercase tracking-wide text-red-300">
                            {issue.category.replace('_', ' ')}
                          </span>
                          <span className="text-red-200/80">Severity {issue.judgeResult?.severity ?? 0}/10</span>
                        </div>
                        <p className="line-clamp-2 text-[11px] leading-relaxed text-slate-300">
                          {issue.judgeResult?.rationale || 'This lane was successfully breached.'}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-400">No detailed lane diagnostics were available, so hardening was generated from run-level evidence.</p>
                )}
              </div>

              <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-emerald-300">Applied Prompt Changes</p>
                <ol className="space-y-2">
                  {mitigation.changes_made.map((change, i) => (
                    <li
                      key={i}
                      className="rounded-lg border border-emerald-500/15 bg-[#090e19] px-2.5 py-2 text-[11px] leading-relaxed text-slate-200"
                    >
                      <span className="mr-2 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-emerald-500/20 px-1 text-[10px] font-semibold text-emerald-300">
                        {i + 1}
                      </span>
                      {change}
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
