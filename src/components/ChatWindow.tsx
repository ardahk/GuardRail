import { useEffect, useRef } from 'react';
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
  };
  index: number;
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
}: ChatWindowProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  const catColor = categoryColors[category] ?? 'bg-slate-500/80 text-slate-950';
  const staggerDelay = `${index * 100}ms`;

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
        </div>
        <StatusBadge status={status} />
      </div>

      {/* Chat area */}
      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto px-4 py-3">
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
          </div>
          <p className="mt-1 line-clamp-2 text-xs text-[#5A4D42]">{judgeResult.rationale}</p>
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
