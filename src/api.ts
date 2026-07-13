import type {
  CreateRunRequest,
  BrowserPreflightResponse,
  Finding,
  FindingReview,
  FindingState,
  JudgeHealth,
  MitigationResponse,
  PlaybookEntry,
  Project,
  ReportResponse,
  RunCreatedResponse,
  RunEvent,
  RunStatus,
  RunComparison,
  TargetAnalysisResponse
} from './types';

const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? 'http://127.0.0.1:8000';
const WS_BASE = (import.meta.env.VITE_WS_BASE as string | undefined) ?? 'ws://127.0.0.1:8000';
const API_TIMEOUT_MS = Number((import.meta.env.VITE_API_TIMEOUT_MS as string | undefined) ?? '60000');

// ── Request wrapper ───────────────────────────────────────────────────────────

async function request<T>(path: string, init?: RequestInit, timeoutMs = API_TIMEOUT_MS): Promise<T> {
  const url = `${API_BASE}${path}`;
  const hasTimeout = Number.isFinite(timeoutMs) && timeoutMs > 0;
  const controller = hasTimeout ? new AbortController() : null;
  const timer = hasTimeout ? setTimeout(() => controller?.abort(), timeoutMs) : null;

  let response: Response;
  try {
    response = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
      signal: controller?.signal,
      ...init,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new Error(`Request timed out after ${timeoutMs}ms: ${url}`);
    }
    throw new Error(`Network error while requesting ${url}`);
  } finally {
    if (timer) clearTimeout(timer);
  }

  if (!response.ok) {
    const raw = await response.text();
    let message = raw;
    let code = `http_${response.status}`;
    try {
      const parsed = JSON.parse(raw) as { detail?: string; error?: { code?: string; message?: string } };
      message = parsed.error?.message || parsed.detail || raw;
      code = parsed.error?.code || code;
    } catch {
      // Preserve non-JSON upstream text.
    }
    throw new Error(`${code}: ${message}`);
  }

  const data = (await response.json()) as T;
  return data;
}

// ── API functions ─────────────────────────────────────────────────────────────

export async function createRun(payload: CreateRunRequest): Promise<RunCreatedResponse> {
  return request<RunCreatedResponse>('/runs', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export async function startRun(runId: string): Promise<RunCreatedResponse> {
  return request<RunCreatedResponse>(`/runs/${runId}/start`, { method: 'POST' });
}

export async function cancelRun(runId: string): Promise<RunCreatedResponse> {
  return request<RunCreatedResponse>(`/runs/${runId}/cancel`, { method: 'POST' });
}

export async function getRunReport(runId: string): Promise<ReportResponse> {
  return request<ReportResponse>(`/runs/${runId}/report`);
}

export async function generateMitigation(
  runId: string,
  vulnerableSystemPrompt?: string
): Promise<MitigationResponse> {
  return request<MitigationResponse>('/mitigations/generate', {
    method: 'POST',
    body: JSON.stringify({ run_id: runId, vulnerable_system_prompt: vulnerableSystemPrompt })
  });
}

export async function applyAndRerun(params: {
  runId: string;
  patchedSystemPrompt: string;
  adminUrl?: string;
}): Promise<{ new_run_id: string; status: RunStatus; source_run_id: string }> {
  return request<{ new_run_id: string; status: RunStatus; source_run_id: string }>('/mitigations/apply-and-rerun', {
    method: 'POST',
    body: JSON.stringify({
      run_id: params.runId,
      patched_system_prompt: params.patchedSystemPrompt,
      admin_url: params.adminUrl
    })
  });
}

export async function analyzeTargetUrl(url: string): Promise<TargetAnalysisResponse> {
  return request<TargetAnalysisResponse>('/targets/analyze', {
    method: 'POST',
    body: JSON.stringify({ url })
  });
}

export async function preflightBrowser(params: {
  url: string;
  projectId?: string;
  selectors?: Record<string, string>;
  safeProbe?: boolean;
  modelFallback?: boolean;
  authorizationAcknowledged: boolean;
}): Promise<BrowserPreflightResponse> {
  return request<BrowserPreflightResponse>('/browser/preflight', {
    method: 'POST',
    body: JSON.stringify({
      url: params.url,
      project_id: params.projectId ?? 'local',
      selectors: params.selectors ?? {},
      safe_probe: params.safeProbe ?? true,
      model_fallback: params.modelFallback ?? false,
      authorization_acknowledged: params.authorizationAcknowledged,
    }),
  }, 180000);
}

export async function getDirectorMemory(domain: string, projectId = 'local'): Promise<{
  domain: string;
  memory: {
    domain: string;
    domain_profile: Record<string, unknown>;
    successful_patterns: Array<Record<string, unknown>>;
    failed_patterns: Array<Record<string, unknown>>;
    last_seen: string;
    confidence: number;
  } | null;
}> {
  const q = encodeURIComponent(domain);
  return request(`/director/memory?domain=${q}&project_id=${encodeURIComponent(projectId)}`);
}

export async function clearDirectorMemory(domain: string, projectId = 'local'): Promise<{ domain: string; cleared: boolean }> {
  const q = encodeURIComponent(domain);
  return request(`/director/memory/clear?domain=${q}&project_id=${encodeURIComponent(projectId)}`, { method: 'POST' });
}

export async function getJudgeHealth(force = false): Promise<JudgeHealth> {
  const suffix = force ? '?force=true' : '';
  return request<JudgeHealth>(`/health/judge${suffix}`);
}

export async function getDirectorPlaybook(
  domain: string,
  limit = 8,
  projectId = 'local',
): Promise<{ domain: string; entries: PlaybookEntry[]; count: number }> {
  const q = encodeURIComponent(domain);
  return request(`/director/playbook?domain=${q}&limit=${limit}&project_id=${encodeURIComponent(projectId)}`);
}

export async function clearDirectorPlaybook(domain: string, projectId = 'local'): Promise<{ domain: string; deleted: number }> {
  const q = encodeURIComponent(domain);
  return request(`/director/playbook/clear?domain=${q}&project_id=${encodeURIComponent(projectId)}`, { method: 'POST' });
}

export async function listProjects(): Promise<{ projects: Project[]; count: number }> {
  return request('/projects');
}

export async function createProject(id: string, name: string, retentionDays = 30): Promise<Project> {
  return request('/projects', {
    method: 'POST',
    body: JSON.stringify({ id, name, retention_days: retentionDays }),
  });
}

export async function compareRuns(baselineRunId: string, candidateRunId: string): Promise<RunComparison> {
  return request(`/runs/compare?baseline_run_id=${encodeURIComponent(baselineRunId)}&candidate_run_id=${encodeURIComponent(candidateRunId)}`);
}

export async function listProjectFindings(
  projectId = 'local',
  runId?: string,
): Promise<{ project_id: string; findings: Finding[]; count: number }> {
  const suffix = runId ? `?run_id=${encodeURIComponent(runId)}` : '';
  return request(`/projects/${encodeURIComponent(projectId)}/findings${suffix}`);
}

export async function getFinding(
  findingId: string,
): Promise<{ finding: Finding; reviews: FindingReview[] }> {
  return request(`/findings/${encodeURIComponent(findingId)}`);
}

export async function reviewFinding(params: {
  findingId: string;
  state: Extract<FindingState, 'pending' | 'confirmed' | 'rejected' | 'needs_retest'>;
  rationale: string;
  reviewer?: string;
}): Promise<Finding> {
  return request(`/findings/${encodeURIComponent(params.findingId)}/review`, {
    method: 'POST',
    body: JSON.stringify({
      state: params.state,
      rationale: params.rationale,
      reviewer: params.reviewer ?? 'local-reviewer',
    }),
  });
}

export function connectRunStream(
  runId: string,
  onEvent: (event: RunEvent) => void,
  onConnectionChange?: (connected: boolean) => void
): () => void {
  const socket = new WebSocket(`${WS_BASE}/ws/runs/${runId}`);

  socket.onopen = () => onConnectionChange?.(true);
  socket.onclose = () => onConnectionChange?.(false);
  socket.onerror = () => onConnectionChange?.(false);

  socket.onmessage = (message) => {
    try {
      const parsed = JSON.parse(message.data) as RunEvent;
      onEvent(parsed);
    } catch {
      // Ignore malformed frames.
    }
  };

  return () => {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
      socket.close();
    }
  };
}

export const runtimeConfig = {
  apiBase: API_BASE,
  wsBase: WS_BASE
};
