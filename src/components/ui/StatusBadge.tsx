import type { LaneStatus } from '../../types';

const statusConfig: Record<LaneStatus, { label: string; bg: string; text: string; dot: string }> = {
  waiting: { label: 'Waiting', bg: 'bg-slate-500/20', text: 'text-slate-300', dot: 'bg-slate-400' },
  attacking: { label: 'Attacking', bg: 'bg-amber-500/20', text: 'text-amber-300', dot: 'bg-amber-400 animate-pulse' },
  judging: { label: 'Judging', bg: 'bg-purple-500/20', text: 'text-purple-300', dot: 'bg-purple-400 animate-pulse' },
  breached: { label: 'Breached', bg: 'bg-red-500/20', text: 'text-red-300', dot: 'bg-red-400' },
  secure: { label: 'Secure', bg: 'bg-emerald-500/20', text: 'text-emerald-300', dot: 'bg-emerald-400' },
  error: { label: 'Error', bg: 'bg-red-500/20', text: 'text-red-300', dot: 'bg-red-400' },
};

export default function StatusBadge({ status }: { status: LaneStatus }) {
  const config = statusConfig[status];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${config.bg} ${config.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${config.dot}`} />
      {config.label}
    </span>
  );
}
