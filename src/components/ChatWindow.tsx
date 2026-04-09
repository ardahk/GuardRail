import { useEffect, useMemo, useRef, useState } from 'react';
import type { ChatMessage, LaneStatus } from '../types';
import ChatBubble from './ui/ChatBubble';
import StatusBadge from './ui/StatusBadge';
import TypingIndicator from './ui/TypingIndicator';

interface ChatWindowProps {
  laneId: string;
  attackId: string;
  category: string;
  status: LaneStatus;
  messages: ChatMessage[];
  isTyping: boolean;
  judgeResult?: {
    result: 'pass' | 'partial_fail' | 'critical_fail';
    severity: number;
    rationale: string;
    confidence?: number;
    flags?: string[];
    adjusted?: boolean;
  };
  index: number;
  laneBadges?: Array<'pivoted' | 'escalated' | 'paused' | 'completed'>;
  mutation?: {
    mutationId?: string;
    mutationFamily?: string;
    tacticTag?: string;
    noveltyScore?: number;
  };
  strategyReason?: string;
}

const categoryColors: Record<string, string> = {
  scope_bypass: 'bg-amber-500/80 text-amber-950',
  prompt_leak: 'bg-red-500/80 text-red-950',
  persona_hijack: 'bg-purple-500/80 text-purple-950',
  data_exfil: 'bg-yellow-500/80 text-yellow-950',
  multi_turn: 'bg-cyan-500/80 text-cyan-950',
};

function categoryLabel(category: string): string {
  return category.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function borderForStatus(status: LaneStatus): string {
  if (status === 'breached') return 'ring-2 ring-red-500/60 shadow-[0_0_24px_rgba(255,70,70,0.15)]';
  if (status === 'secure') return 'ring-2 ring-emerald-500/60 shadow-[0_0_24px_rgba(74,222,128,0.15)]';
  if (status === 'pivoted') return 'ring-2 ring-cyan-500/50';
  if (status === 'escalated') return 'ring-2 ring-orange-500/50';
  return '';
}

export default function ChatWindow({
  laneId,
  attackId,
  category,
  status,
  messages,
  isTyping,
  judgeResult,
  index,
  laneBadges = [],
  mutation,
  strategyReason,
}: ChatWindowProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [showReasoning, setShowReasoning] = useState(false);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  const catColor = categoryColors[category] ?? 'bg-slate-500/80 text-slate-950';
  const staggerDelay = `${index * 100}ms`;
  const historyReport = useMemo(() => {
    const attackerTurns = messages.filter((m) => m.role === 'attacker').length;
    const victimTurns = messages.filter((m) => m.role === 'victim').length;
    const lastVictim = [...messages].reverse().find((m) => m.role === 'victim')?.text ?? '';
    const trimmed = lastVictim.length > 180 ? `${lastVictim.slice(0, 180)}...` : lastVictim;
    return {
      attackerTurns,
      victimTurns,
      lastVictim: trimmed || 'No victim response captured.',
    };
  }, [messages]);

  return (
    <div
      className={`animate-window-in flex flex-col overflow-hidden rounded-2xl bg-[#F5F0EB] shadow-xl ${borderForStatus(status)}`}
      style={{ animationDelay: staggerDelay, height: '480px' }}
    >
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-[#E5DDD5] bg-white px-4 py-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-[#A91D1D] shadow-sm">
          <span className="text-sm">🌶️</span>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-[#2C2017]">Pepper</span>
            <span className={`rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider ${catColor}`}>
              {categoryLabel(category)}
            </span>
          </div>
          <p className="truncate text-[10px] text-[#8B7B6E]">{attackId}</p>
          {laneBadges.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {laneBadges.slice(-3).map((badge, idx) => (
                <span
                  key={`${badge}-${idx}`}
                  className="rounded-full bg-slate-200 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-slate-700"
                >
                  {badge}
                </span>
              ))}
            </div>
          )}
          {mutation?.tacticTag && (
            <p className="mt-1 text-[10px] text-[#7b6d61]">
              {mutation.tacticTag} · {mutation.mutationFamily || 'generic'} · novelty {Math.round(mutation.noveltyScore ?? 0)}%
            </p>
          )}
        </div>
        <StatusBadge status={status} />
      </div>

      {/* Chat area */}
      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto px-4 py-3">
        {status === 'error' && strategyReason && (
          <div className="rounded-lg border border-red-300/60 bg-red-50 px-3 py-2 text-xs text-red-800">
            {strategyReason}
          </div>
        )}
        {messages.length === 0 && !isTyping && (
          <p className="py-8 text-center text-sm text-[#8B7B6E]">Waiting for attack to begin...</p>
        )}
        {messages.map((msg, i) => (
          <ChatBubble key={`${laneId}-${i}`} role={msg.role} text={msg.text} timestamp={msg.timestamp} />
        ))}
        {isTyping && (
          <div className="flex gap-2.5">
            <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[#A91D1D]">
              <span className="text-xs font-bold text-white">🌶️</span>
            </div>
            <div className="rounded-2xl rounded-tl-md bg-[#6B5B4F] px-4 shadow-sm">
              <TypingIndicator />
            </div>
          </div>
        )}
      </div>

      {/* Judge verdict overlay */}
      {judgeResult && (status === 'breached' || status === 'secure') && (
        <div className="animate-fade-slide-in border-t border-[#E5DDD5] bg-white/90 px-4 py-3">
          <div className="flex items-center gap-2">
            {judgeResult.result === 'pass' ? (
              <span className="rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-bold uppercase text-emerald-700">
                Secure
              </span>
            ) : (
              <span className="rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-bold uppercase text-red-700">
                Breached
              </span>
            )}
            <span className="text-xs text-[#8B7B6E]">Severity: {judgeResult.severity}/10</span>
            {typeof judgeResult.confidence === 'number' && (
              <span className="text-xs text-[#8B7B6E]">Confidence: {Math.round(judgeResult.confidence * 100)}%</span>
            )}
            {judgeResult.adjusted && (
              <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold uppercase text-amber-700">
                normalized
              </span>
            )}
          </div>
          <p className="mt-1 line-clamp-2 text-xs text-[#5A4D42]">{judgeResult.rationale}</p>
          {!!judgeResult.flags?.length && (
            <p className="mt-1 line-clamp-1 text-[11px] text-[#8B7B6E]">Flags: {judgeResult.flags.join(', ')}</p>
          )}
          <button
            type="button"
            onClick={() => setShowReasoning((v) => !v)}
            className="mt-2 rounded-md border border-[#d7c8b8] bg-[#f8f4ee] px-2 py-1 text-[11px] font-semibold text-[#5A4D42]"
          >
            {showReasoning ? 'Hide Full Reasoning' : 'View Full Reasoning'}
          </button>
          {showReasoning && (
            <div className="mt-2 rounded-lg border border-[#d7c8b8] bg-[#f8f4ee] p-2 text-[11px] text-[#4b4038]">
              <p className="font-semibold">Full Judge Reasoning</p>
              <p className="mt-1 whitespace-pre-wrap">{judgeResult.rationale}</p>
              <p className="mt-2 font-semibold">Brief Chat Report</p>
              <p className="mt-1">
                {historyReport.attackerTurns} attacker turns, {historyReport.victimTurns} victim turns.
                Final victim response: {historyReport.lastVictim}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Fake input bar */}
      <div className="flex items-center gap-2 border-t border-[#E5DDD5] bg-white px-4 py-2.5">
        <span className="text-[#8B7B6E]">📎</span>
        <div className="flex-1 rounded-full bg-[#F5F0EB] px-4 py-2 text-sm text-[#8B7B6E]">
          Type message here
        </div>
        <button className="flex h-8 w-8 items-center justify-center rounded-full bg-[#6B5B4F] text-white" disabled>
          ▶
        </button>
      </div>
    </div>
  );
}
