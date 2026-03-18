export type Intensity = 'low' | 'medium' | 'high';

export type RunStatus = 'created' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface TargetConfig {
  base_url: string;
  api_key: string;
  model: string;
  admin_url?: string;
}

export interface CreateRunRequest {
  target: TargetConfig;
  intensity: Intensity;
  system_prompt: string;
  max_turns?: number;
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

export interface ChatMessage {
  role: 'attacker' | 'victim';
  text: string;
  timestamp: string;
}

export type LaneStatus = 'waiting' | 'attacking' | 'judging' | 'breached' | 'secure' | 'error';

export interface LaneView {
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
}
