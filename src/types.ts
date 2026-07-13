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
  project_id?: string;
  authorization_acknowledged?: boolean;
  coverage_profile?: string;
  run_budget?: number;
  hypothesis_fanout_limit?: number;
  review_policy?: 'risk_based' | 'automated' | 'review_all';
  browser_model_fallback?: boolean;
}

export interface BrowserObservation {
  schema_version: string;
  project_id: string;
  target_url: string;
  route_pattern: string;
  widget_fingerprint: string;
  capture_confidence: number;
  selected_controls: Record<string, string>;
  candidates: Array<Record<string, unknown>>;
  action_verification: Record<string, boolean>;
  response_candidates: Array<Record<string, unknown>>;
  timings_ms: Record<string, number>;
  errors: string[];
  context_label?: string;
}

export interface BrowserPreflightResponse {
  ok: boolean;
  observation: BrowserObservation;
  probe_response?: string | null;
  selector_overrides: Record<string, string>;
  model_fallback: { enabled: boolean; used: boolean; reason: string };
}

export type FindingState = 'observed' | 'suspected' | 'pending' | 'confirmed' | 'rejected' | 'needs_retest' | 'not_tested';

export interface FindingEvidence {
  type: string;
  source: string;
  excerpt: string;
  start_index?: number;
  end_index?: number;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  run_id: string;
  project_id: string;
  lane_id: string;
  category: string;
  title: string;
  state: FindingState;
  severity: number;
  confidence: number;
  evidence: FindingEvidence[];
  standards_mapping: string[];
  remediation: string[];
  hypothesis_id?: string;
  reproduction_count: number;
  provenance: Record<string, unknown>;
  reproduction_transcript: Array<{ role: string; content: string }>;
  attack_evolution: string[];
  impacted_capability: string;
  confirmation_status: string;
  created_at: string;
}

export interface FindingReview {
  id: number;
  finding_id: string;
  state: FindingState;
  rationale: string;
  reviewer: string;
  created_at: string;
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
  judge_result?: 'pass' | 'partial_fail' | 'critical_fail' | 'unjudged';
  severity?: number;
  rationale_summary?: string;
  mutation_id?: string;
  mutation_family?: string;
  tactic_tag?: string;
  novelty_score?: number;
  judge_confidence?: number;
  judge_flags?: string[];
  normalized_result?: 'pass' | 'partial_fail' | 'critical_fail' | 'unjudged';
  normalized_severity?: number;
  attack_family?: string;
  mechanism?: string;
  example_incident?: string;
  input_channel?: string;
  expected_safe_behavior?: string;
  failure_signal?: string;
  recommended_mitigation?: string;
  judge_status?: 'judged' | 'unjudged' | 'error' | string;
  mastermind?: MastermindState;
  error?: string;
  capture_confidence?: number;
  finding_state?: FindingState;
  hypothesis_id?: string;
  standards_mapping?: string[];
  reproduction_count?: number;
  provenance?: Record<string, unknown>;
  purpose?: 'coverage' | 'confirmation';
}

export interface MastermindState {
  observed_scope?: string;
  allowed_topics?: string[];
  blocked_topics?: string[];
  refusal_reason?: string;
  response_pattern?: string;
  leaked_operational_hints?: string[];
  last_safe_boundary?: string;
  next_angle?: string;
  risk_signal?: string;
  turn_phase?: 'rapport' | 'probe' | 'escalate' | 'pivot' | string;
  phase_turn_count?: number;
  bot_helpfulness_signal?: 'engaged' | 'redirecting' | 'stonewalling' | 'unknown' | string;
  target_vocabulary?: string[];
}

export interface PlaybookEntry {
  attack_family?: string;
  tactic_tag?: string;
  category?: string;
  mutation_family?: string;
  rendered_prompt?: string;
  bot_response_excerpt?: string;
  mastermind_snapshot?: Record<string, unknown>;
  judge_result?: string;
  severity?: number;
  judge_confidence?: number;
  hit_count?: number;
  last_seen?: string;
}

export interface JudgeHealth {
  ok: boolean;
  model: string | null;
  latency_ms: number;
  error_message: string | null;
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
  coverage?: Record<string, unknown>;
  findings?: Array<Record<string, unknown>>;
  schema_version?: string;
  confirmation_lanes?: number;
  successful_confirmations?: number;
}

export interface Project {
  id: string;
  name: string;
  retention_days: number;
  created_at: string;
}

export interface RunComparison {
  schema_version: string;
  baseline_run_id: string;
  candidate_run_id: string;
  comparable: boolean;
  comparability_reasons: string[];
  baseline: { successful_attacks: number; success_rate: number; critical_failures: number; coverage_complete: boolean };
  candidate: { successful_attacks: number; success_rate: number; critical_failures: number; coverage_complete: boolean };
  delta: { successful_attacks: number; success_rate: number; critical_failures: number };
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
  | 'unjudged'
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
  evaluation?: {
    attackFamily?: string;
    mechanism?: string;
    exampleIncident?: string;
    inputChannel?: string;
    expectedSafeBehavior?: string;
    failureSignal?: string;
    recommendedMitigation?: string;
    judgeStatus?: string;
  };
  mastermind?: MastermindState;
  judgeResult?: {
    result: 'pass' | 'partial_fail' | 'critical_fail' | 'unjudged';
    severity: number;
    rationale: string;
    confidence?: number;
    flags?: string[];
    adjusted?: boolean;
  };
  turnPhase?: 'rapport' | 'probe' | 'escalate' | 'pivot' | string;
  phaseHistory?: Array<{ from: string; to: string; step: number }>;
  playbookHits?: number;
}

export type RunStage = 'idle' | 'analyzing' | 'planning' | 'connecting' | 'running_lanes' | 'completed' | 'cancelled' | 'failed';

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
  judgeHealth?: JudgeHealth;
  judgeErrorMessage?: string;
  playbookSeeded?: {
    domain: string;
    count: number;
    entries: PlaybookEntry[];
  };
  playbookHits?: number;
}
