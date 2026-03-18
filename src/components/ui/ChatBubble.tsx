interface ChatBubbleProps {
  role: 'attacker' | 'victim';
  text: string;
  timestamp: string;
  botName?: string;
}

function formatTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function ChatBubble({ role, text, timestamp, botName = 'Pepper' }: ChatBubbleProps) {
  if (role === 'victim') {
    return (
      <div className="animate-fade-slide-in flex gap-2.5 pr-12">
        <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[#A91D1D] shadow-sm">
          <span className="text-xs font-bold text-white">🌶️</span>
        </div>
        <div>
          <div className="rounded-2xl rounded-tl-md bg-[#6B5B4F] px-4 py-2.5 text-sm text-white shadow-sm">
            {text}
          </div>
          <p className="mt-1 ml-1 text-[11px] text-[#8B7B6E]">{botName} | {formatTime(timestamp)}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="animate-fade-slide-in flex justify-end gap-2.5 pl-12">
      <div>
        <div className="rounded-2xl rounded-tr-md bg-[#D4C5B2] px-4 py-2.5 text-sm text-[#2C2017] shadow-sm">
          {text}
        </div>
        <p className="mt-1 mr-1 text-right text-[11px] text-[#8B7B6E]">Attacker | {formatTime(timestamp)}</p>
      </div>
      <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-700 shadow-sm">
        <span className="text-xs">🤖</span>
      </div>
    </div>
  );
}
