import {
  CreateRunRequest,
  MitigationResponse,
  ReportResponse,
  RunCreatedResponse,
  RunEvent,
  RunStatus
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
    const detail = await response.text();
    throw new Error(`HTTP ${response.status}: ${detail}`);
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
