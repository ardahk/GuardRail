export type Intensity = 'low' | 'medium' | 'high';

export type RunStatus = 'created' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface TargetConfig {
  base_url: string;
  api_key: string;
  model: string;
  admin_url?: string;
  target_type?: 'api' | 'browser';
  playwright_target_url?: string;
  playwright_selectors?: Record<string, string>;
}

export interface CreateRunRequest {
  target: TargetConfig;
  intensity: Intensity;
  system_prompt: string;
  max_turns?: number;
  attack_categories?: string[];
  auto_analyzed_context?: Record<string, unknown>;
  director_enabled?: boolean;
}

export interface RunCreatedResponse {
  id: string;
  status: RunStatus;
}

export interface RunEvent {
  run_id: string;
  type: string;
  ts: string;
  payload: Record<string, unknown>;
}

export interface LaneResult {
  lane_id: string;
  attack_id: string;
  category: string;
  success: boolean;
  attempts: number;
  responses: string[];
  judge_result?: 'pass' | 'partial_fail' | 'critical_fail';
  severity?: number;
  rationale_summary?: string;
  mutation_id?: string;
  mutation_family?: string;
  tactic_tag?: string;
  novelty_score?: number;
  judge_confidence?: number;
  judge_flags?: string[];
  normalized_result?: 'pass' | 'partial_fail' | 'critical_fail';
  normalized_severity?: number;
  error?: string;
}

export interface CategorySummary {
  category: string;
  total: number;
  successes: number;
  average_severity: number;
  critical_failures: number;
}

export interface RunReport {
  run_id: string;
  status: RunStatus;
  intensity: Intensity;
  total_attacks: number;
  successful_attacks: number;
  success_rate: number;
  total_critical_failures: number;
  categories: CategorySummary[];
  lanes: LaneResult[];
}

export interface ReportResponse {
  run_id: string;
  status: RunStatus;
  request: CreateRunRequest;
  report: RunReport | null;
  events: RunEvent[];
}

export interface MitigationResponse {
  run_id: string;
  patched_system_prompt: string;
  changes_made: string[];
  source_lane?: string;
  note?: string;
}

export interface TargetAnalysisResponse {
  target_url: string;
  summary: string;
  domain: string;
  likely_bot_purpose: string;
  recommended_attack_categories: string[];
  risk_hypotheses: string[];
  context_hint_for_judge: string;
}

export interface ChatMessage {
  role: 'attacker' | 'victim';
  text: string;
  timestamp: string;
}

export type LaneStatus =
  | 'waiting'
  | 'attacking'
  | 'judging'
  | 'pivoted'
  | 'escalated'
  | 'paused'
  | 'breached'
  | 'secure'
  | 'error';

export interface LaneView {
  laneId: string;
  attackId: string;
  category: string;
  status: LaneStatus;
  messages: ChatMessage[];
  isTyping: boolean;
  laneBadges?: Array<'pivoted' | 'escalated' | 'paused' | 'completed'>;
  strategyReason?: string;
  decisionSource?: 'director' | 'fallback' | string;
  mutation?: {
    mutationId?: string;
    mutationFamily?: string;
    tacticTag?: string;
    noveltyScore?: number;
  };
  judgeResult?: {
    result: 'pass' | 'partial_fail' | 'critical_fail';
    severity: number;
    rationale: string;
    confidence?: number;
    flags?: string[];
    adjusted?: boolean;
  };
}

export type RunStage = 'idle' | 'analyzing' | 'planning' | 'connecting' | 'running_lanes' | 'completed' | 'failed';

export interface DirectorPanelState {
  stage: RunStage;
  lastDecision?: {
    laneId?: string;
    action: string;
    reason: string;
    decisionSource: string;
    tacticHint?: string;
    ts?: string;
  };
  recentDecisions?: Array<{
    laneId?: string;
    action: string;
    reason: string;
    decisionSource: string;
    tacticHint?: string;
    ts?: string;
  }>;
  rebalance?: {
    message: string;
    focusCategory?: string;
    distribution?: Record<string, unknown>;
    decisionSource?: string;
  };
  memory?: {
    domain: string;
    confidence: number;
  };
}
