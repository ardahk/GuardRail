import { useCallback, useEffect, useMemo, useState } from 'react';
import { getFinding, listProjectFindings, reviewFinding } from '../api';
import type { Finding, FindingReview, FindingState } from '../types';

const reviewStates = ['confirmed', 'rejected', 'needs_retest'] as const;

export default function FindingsReview({ runId, projectId = 'local' }: { runId: string; projectId?: string }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [reviews, setReviews] = useState<FindingReview[]>([]);
  const [stateFilter, setStateFilter] = useState<'all' | FindingState>('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [reviewState, setReviewState] = useState<(typeof reviewStates)[number]>('confirmed');
  const [rationale, setRationale] = useState('');
  const [reviewer, setReviewer] = useState('local-reviewer');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    if (!runId) return;
    setBusy(true);
    setError('');
    try {
      const response = await listProjectFindings(projectId, runId);
      setFindings(response.findings);
      setSelectedId((current) => current || response.findings[0]?.id || '');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }, [projectId, runId]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!selectedId) { setReviews([]); return; }
    void getFinding(selectedId)
      .then((result) => setReviews(result.reviews))
      .catch((err) => setError((err as Error).message));
  }, [selectedId]);

  const categories = useMemo(
    () => [...new Set(findings.map((item) => item.category))].sort(),
    [findings],
  );
  const filtered = findings.filter((item) => (
    (stateFilter === 'all' || item.state === stateFilter)
    && (categoryFilter === 'all' || item.category === categoryFilter)
  ));
  const selected = findings.find((item) => item.id === selectedId) ?? null;

  async function submitReview() {
    if (!selected || !rationale.trim()) return;
    setBusy(true);
    setError('');
    try {
      await reviewFinding({
        findingId: selected.id,
        state: reviewState,
        rationale: rationale.trim(),
        reviewer: reviewer.trim() || 'local-reviewer',
      });
      setRationale('');
      await refresh();
      const detail = await getFinding(selected.id);
      setReviews(detail.reviews);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!runId) return null;
  return (
    <section className="mx-auto mt-5 max-w-7xl rounded-2xl border border-violet-400/20 bg-[#080d17]/90 p-4 text-slate-200">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-violet-300">Human Review Queue</p>
          <p className="mt-1 text-xs text-slate-400">Confirm evidence-backed findings or reject false positives before reporting.</p>
        </div>
        <div className="flex gap-2">
          <select value={stateFilter} onChange={(event) => setStateFilter(event.target.value as 'all' | FindingState)} className="rounded-lg border border-white/10 bg-slate-950 px-2 py-1 text-xs">
            <option value="all">All states</option>
            {['pending', 'suspected', 'confirmed', 'rejected', 'needs_retest'].map((state) => <option key={state} value={state}>{state.replace('_', ' ')}</option>)}
          </select>
          <select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)} className="rounded-lg border border-white/10 bg-slate-950 px-2 py-1 text-xs">
            <option value="all">All categories</option>
            {categories.map((category) => <option key={category} value={category}>{category.replace('_', ' ')}</option>)}
          </select>
          <button type="button" onClick={() => void refresh()} disabled={busy} className="rounded-lg border border-violet-300/25 bg-violet-300/10 px-3 py-1 text-xs text-violet-100">Refresh</button>
        </div>
      </div>

      {error && <p className="mt-3 rounded-lg border border-red-400/20 bg-red-400/10 p-2 text-xs text-red-200">{error}</p>}
      {findings.length === 0 ? (
        <p className="mt-4 rounded-xl border border-white/10 bg-black/20 p-4 text-xs text-slate-400">No findings require review for this run.</p>
      ) : (
        <div className="mt-4 grid gap-3 lg:grid-cols-[minmax(260px,0.8fr)_minmax(0,1.7fr)]">
          <div className="max-h-[34rem] space-y-2 overflow-auto pr-1">
            {filtered.map((finding) => (
              <button key={finding.id} type="button" onClick={() => setSelectedId(finding.id)} className={`w-full rounded-xl border p-3 text-left ${selectedId === finding.id ? 'border-violet-300/45 bg-violet-300/10' : 'border-white/10 bg-black/20 hover:border-white/20'}`}>
                <div className="flex items-center justify-between gap-2 text-[10px] uppercase tracking-wide">
                  <span className="text-violet-200">{finding.category.replace('_', ' ')}</span>
                  <span className="text-slate-400">Severity {finding.severity}/10</span>
                </div>
                <p className="mt-1 text-xs font-semibold text-slate-100">{finding.title}</p>
                <p className="mt-1 text-[10px] text-slate-400">{finding.state.replace('_', ' ')} · {Math.round(finding.confidence * 100)}% confidence · {finding.reproduction_count} reproduction(s)</p>
              </button>
            ))}
          </div>

          {selected && (
            <div className="rounded-xl border border-white/10 bg-black/20 p-4">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div><h3 className="text-sm font-semibold">{selected.title}</h3><p className="mt-1 text-[11px] text-slate-400">{selected.lane_id} · hypothesis {selected.hypothesis_id || 'none'}</p></div>
                <span className="rounded-full border border-violet-300/25 bg-violet-300/10 px-2 py-1 text-[10px] uppercase text-violet-200">{selected.state.replace('_', ' ')}</span>
              </div>
              <div className="mt-3 flex flex-wrap gap-2 text-[10px]">
                <span className="rounded-full border border-cyan-300/20 bg-cyan-300/10 px-2 py-1 text-cyan-100">Capability: {selected.impacted_capability || 'chat'}</span>
                <span className="rounded-full border border-emerald-300/20 bg-emerald-300/10 px-2 py-1 text-emerald-100">Confirmation: {(selected.confirmation_status || 'not scheduled').replace('_', ' ')}</span>
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <div><p className="text-[10px] uppercase text-slate-500">Evidence</p><div className="mt-1 space-y-1">{selected.evidence.map((item, index) => <div key={`${item.type}-${index}`} className="rounded-lg border border-white/8 bg-slate-950 p-2 text-[11px]"><span className="text-cyan-300">{item.type}</span><p className="mt-1 break-words text-slate-300">{item.excerpt || 'Structured signal'}</p><p className="mt-1 text-[9px] text-slate-500">{item.source} · {Math.round(item.confidence * 100)}%</p></div>)}</div></div>
                <div><p className="text-[10px] uppercase text-slate-500">Remediation</p><ul className="mt-1 space-y-1 text-[11px] text-slate-300">{selected.remediation.map((item) => <li key={item} className="rounded-lg border border-white/8 bg-slate-950 p-2">{item}</li>)}</ul><p className="mt-3 text-[10px] uppercase text-slate-500">Standards</p><p className="mt-1 text-[11px] text-amber-200">{selected.standards_mapping.join(' · ') || 'Unmapped'}</p></div>
              </div>
              {(selected.reproduction_transcript?.length > 0 || selected.attack_evolution?.length > 0) && (
                <details className="mt-3 rounded-lg border border-white/8 bg-slate-950 p-2 text-[10px]">
                  <summary className="cursor-pointer text-slate-400">Reproduction and attack evolution</summary>
                  {selected.reproduction_transcript?.length > 0 && (
                    <div className="mt-2 space-y-1">{selected.reproduction_transcript.map((item, index) => (
                      <p key={`${item.role}-${index}`} className="rounded border border-white/5 p-2 text-slate-300"><span className="font-semibold uppercase text-cyan-300">{item.role}</span>: {item.content}</p>
                    ))}</div>
                  )}
                  {selected.attack_evolution?.length > 0 && <ol className="mt-2 list-decimal space-y-1 pl-4 text-slate-300">{selected.attack_evolution.map((step, index) => <li key={`${step}-${index}`}>{step}</li>)}</ol>}
                </details>
              )}
              <details className="mt-3 rounded-lg border border-white/8 bg-slate-950 p-2 text-[10px]"><summary className="cursor-pointer text-slate-400">Verdict provenance</summary><pre className="mt-2 overflow-auto whitespace-pre-wrap text-slate-300">{JSON.stringify(selected.provenance, null, 2)}</pre></details>
              <div className="mt-3 rounded-xl border border-violet-300/15 bg-violet-300/5 p-3">
                <div className="grid gap-2 sm:grid-cols-2"><input value={reviewer} onChange={(event) => setReviewer(event.target.value)} placeholder="Reviewer" className="rounded-lg border border-white/10 bg-slate-950 px-2 py-1.5 text-xs"/><select value={reviewState} onChange={(event) => setReviewState(event.target.value as (typeof reviewStates)[number])} className="rounded-lg border border-white/10 bg-slate-950 px-2 py-1.5 text-xs">{reviewStates.map((state) => <option key={state} value={state}>{state.replace('_', ' ')}</option>)}</select></div>
                <textarea value={rationale} onChange={(event) => setRationale(event.target.value)} rows={3} placeholder="Required reviewer rationale" className="mt-2 w-full rounded-lg border border-white/10 bg-slate-950 p-2 text-xs"/>
                <button type="button" onClick={() => void submitReview()} disabled={busy || !rationale.trim()} className="mt-2 rounded-lg bg-violet-500 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40">Save review</button>
              </div>
              {reviews.length > 0 && <div className="mt-3"><p className="text-[10px] uppercase text-slate-500">Review history</p>{reviews.map((review) => <div key={review.id} className="mt-1 rounded-lg border border-white/8 p-2 text-[10px] text-slate-300"><span className="text-violet-200">{review.state.replace('_', ' ')}</span> by {review.reviewer}: {review.rationale}</div>)}</div>}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
