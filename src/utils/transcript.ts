import type { JudgeHealth, LaneView, PlaybookEntry, RunReport, RunStatus } from '../types';

interface BuildTranscriptInput {
  status: RunStatus;
  targetType: 'api' | 'browser';
  targetUrl?: string;
  report: RunReport | null;
  lanes: LaneView[];
  judgeHealth?: JudgeHealth;
  judgeErrorMessage?: string;
  playbookSeeded?: { domain: string; count: number; entries: PlaybookEntry[] };
  playbookHits?: number;
}

function formatTime(iso: string): string {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleTimeString();
  } catch {
    return iso;
  }
}

function bullet(label: string, value: unknown): string {
  if (value === undefined || value === null || value === '') return '';
  return `- **${label}:** ${value}\n`;
}

function laneStatusLine(lane: LaneView): string {
  const parts: string[] = [`status: ${lane.status}`];
  if (lane.judgeResult) {
    parts.push(`result: ${lane.judgeResult.result}`);
    parts.push(`severity: ${lane.judgeResult.severity}/10`);
    if (typeof lane.judgeResult.confidence === 'number') {
      parts.push(`confidence: ${Math.round(lane.judgeResult.confidence * 100)}%`);
    }
  }
  if (lane.evaluation?.judgeStatus) parts.push(`judge_status: ${lane.evaluation.judgeStatus}`);
  if (lane.turnPhase) parts.push(`phase: ${lane.turnPhase}`);
  if (lane.mutation?.tacticTag) parts.push(`tactic: ${lane.mutation.tacticTag}`);
  if (typeof lane.playbookHits === 'number' && lane.playbookHits > 0) {
    parts.push(`playbook_hits: ${lane.playbookHits}`);
  }
  return parts.join(' · ');
}

export function buildTranscriptMarkdown(input: BuildTranscriptInput): string {
  const { status, targetType, targetUrl, report, lanes, judgeHealth, judgeErrorMessage, playbookSeeded } = input;

  const ts = new Date().toISOString();
  const breached = lanes.filter((l) => l.status === 'breached').length;
  const secure = lanes.filter((l) => l.status === 'secure').length;
  const unjudged = lanes.filter((l) => l.status === 'unjudged').length;
  const errored = lanes.filter((l) => l.status === 'error').length;

  const out: string[] = [];
  out.push(`# GuardRail Run Transcript`);
  out.push('');
  out.push(`*Exported ${ts}*`);
  out.push('');
  out.push('## Summary');
  out.push('');
  out.push(bullet('Status', status).trim());
  if (targetUrl) out.push(bullet('Target', `${targetUrl} (${targetType})`).trim());
  else out.push(bullet('Target type', targetType).trim());
  if (report) {
    out.push(bullet('Intensity', report.intensity).trim());
    out.push(bullet('Lanes', report.total_attacks).trim());
    out.push(bullet('Successful attacks', report.successful_attacks).trim());
    out.push(bullet('Critical failures', report.total_critical_failures).trim());
    out.push(bullet('Attack success rate', `${Math.round(report.success_rate * 100)}%`).trim());
  } else {
    out.push(bullet('Lanes', lanes.length).trim());
  }
  out.push(bullet('Breached', breached).trim());
  out.push(bullet('Secure', secure).trim());
  out.push(bullet('Unjudged', unjudged).trim());
  if (errored) out.push(bullet('Errored', errored).trim());

  if (judgeHealth) {
    out.push('');
    out.push('## Judge health');
    out.push('');
    out.push(bullet('OK', judgeHealth.ok).trim());
    out.push(bullet('Model', judgeHealth.model ?? 'unknown').trim());
    out.push(bullet('Latency', `${judgeHealth.latency_ms} ms`).trim());
    if (judgeHealth.error_message) {
      out.push(bullet('Error', judgeHealth.error_message).trim());
    }
  }
  if (judgeErrorMessage && (!judgeHealth || judgeHealth.ok)) {
    out.push('');
    out.push(bullet('Judge degradation', judgeErrorMessage).trim());
  }

  if (playbookSeeded && playbookSeeded.count > 0) {
    out.push('');
    out.push('## Memory (playbook entries loaded)');
    out.push('');
    out.push(bullet('Domain', playbookSeeded.domain).trim());
    out.push(bullet('Entries', playbookSeeded.count).trim());
    playbookSeeded.entries.slice(0, 10).forEach((e, i) => {
      out.push('');
      out.push(`### Memory entry ${i + 1}`);
      out.push('');
      out.push(bullet('Tactic', e.tactic_tag).trim());
      out.push(bullet('Family', e.attack_family).trim());
      out.push(bullet('Category', e.category).trim());
      out.push(bullet('Severity', e.severity).trim());
      out.push(bullet('Judge result', e.judge_result).trim());
      out.push(bullet('Hit count', e.hit_count).trim());
      out.push(bullet('Last seen', e.last_seen).trim());
      if (e.rendered_prompt) {
        out.push('');
        out.push('Framing:');
        out.push('```');
        out.push(e.rendered_prompt);
        out.push('```');
      }
    });
  }

  out.push('');
  out.push('## Lanes');

  lanes.forEach((lane, idx) => {
    out.push('');
    out.push(`### Lane ${idx + 1} — ${lane.attackId} (${lane.category})`);
    out.push('');
    out.push(`*${laneStatusLine(lane)}*`);
    out.push('');
    if (lane.judgeResult?.rationale) {
      out.push(`**Judge rationale:** ${lane.judgeResult.rationale}`);
      out.push('');
    }
    if (lane.judgeResult?.flags?.length) {
      out.push(`**Flags:** ${lane.judgeResult.flags.join(', ')}`);
      out.push('');
    }
    if (lane.evaluation?.attackFamily) {
      out.push(bullet('Attack family', lane.evaluation.attackFamily).trim());
    }
    if (lane.evaluation?.mechanism) {
      out.push(bullet('Mechanism', lane.evaluation.mechanism).trim());
    }
    if (lane.evaluation?.expectedSafeBehavior) {
      out.push(bullet('Expected safe behavior', lane.evaluation.expectedSafeBehavior).trim());
    }
    if (lane.evaluation?.failureSignal) {
      out.push(bullet('Failure signal', lane.evaluation.failureSignal).trim());
    }
    if (lane.strategyReason) {
      out.push(bullet('Strategy reason', lane.strategyReason).trim());
    }
    if (lane.mastermind) {
      const m = lane.mastermind;
      out.push('');
      out.push('**Mastermind:**');
      if (m.observed_scope) out.push(`- scope: ${m.observed_scope}`);
      if (m.allowed_topics?.length) out.push(`- allowed_topics: ${m.allowed_topics.join(', ')}`);
      if (m.blocked_topics?.length) out.push(`- blocked_topics: ${m.blocked_topics.join(', ')}`);
      if (m.leaked_operational_hints?.length) {
        out.push(`- leaked_hints: ${m.leaked_operational_hints.join(', ')}`);
      }
      if (m.next_angle) out.push(`- next_angle: ${m.next_angle}`);
      if (m.bot_helpfulness_signal) out.push(`- helpfulness: ${m.bot_helpfulness_signal}`);
      if (m.turn_phase) out.push(`- turn_phase: ${m.turn_phase}`);
    }
    if (lane.phaseHistory?.length) {
      out.push('');
      out.push('**Phase transitions:**');
      lane.phaseHistory.forEach((p) => {
        out.push(`- step ${p.step}: ${p.from} → ${p.to}`);
      });
    }
    out.push('');
    out.push('**Messages:**');
    out.push('');
    if (lane.messages.length === 0) {
      out.push('_(no messages captured)_');
    } else {
      lane.messages.forEach((msg, i) => {
        const who = msg.role === 'attacker' ? 'Attacker' : 'Pepper';
        out.push(`#### ${i + 1}. ${who} · ${formatTime(msg.timestamp)}`);
        out.push('');
        out.push(msg.text);
        out.push('');
      });
    }
  });

  return out.filter((l) => l !== undefined).join('\n').replace(/\n{3,}/g, '\n\n');
}

export async function copyTranscriptToClipboard(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall through to legacy path.
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
