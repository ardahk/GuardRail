from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Intensity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RunStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingState(str, Enum):
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    NEEDS_RETEST = "needs_retest"
    NOT_TESTED = "not_tested"


class ReviewPolicy(str, Enum):
    RISK_BASED = "risk_based"
    AUTOMATED = "automated"
    REVIEW_ALL = "review_all"


class TargetConfig(BaseModel):
    base_url: str
    api_key: str
    model: str
    admin_url: str | None = None
    target_type: str = "api"
    playwright_target_url: str | None = None
    playwright_selectors: dict | None = None


class AttackDefinition(BaseModel):
    id: str
    category: str
    prompt_template: str
    severity_weight: float = Field(ge=0)
    success_criteria: list[str]
    multi_turn_steps: list[str] | None = None
    attack_family: str | None = None
    mechanism: str | None = None
    example_incident: str | None = None
    input_channel: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    expected_safe_behavior: str | None = None
    failure_signal: str | None = None
    mitigation: str | None = None
    turn_strategy: str | None = None


class CreateRunRequest(BaseModel):
    target: TargetConfig
    intensity: Intensity = Intensity.MEDIUM
    system_prompt: str = ""
    max_turns: int | None = Field(default=None, ge=1, le=10)
    attack_categories: list[str] | None = None
    auto_analyzed_context: dict[str, Any] | None = None
    director_enabled: bool = True
    project_id: str = Field(default="local", min_length=1, max_length=80)
    authorization_acknowledged: bool = False
    coverage_profile: str = "owasp_llm_2025"
    run_budget: int = Field(default=40, ge=1, le=500)
    hypothesis_fanout_limit: int = Field(default=3, ge=0, le=10)
    review_policy: ReviewPolicy = ReviewPolicy.RISK_BASED
    browser_model_fallback: bool = False


class RunCreatedResponse(BaseModel):
    id: str
    status: RunStatus


class RunEvent(BaseModel):
    run_id: str
    type: str
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload: dict[str, Any] = Field(default_factory=dict)


class LaneResult(BaseModel):
    lane_id: str
    attack_id: str
    category: str
    success: bool
    attempts: int
    responses: list[str] = Field(default_factory=list)
    judge_result: str | None = None
    severity: int | None = None
    rationale_summary: str | None = None
    evidence_spans: list[dict[str, Any]] = Field(default_factory=list)
    mitigation: dict[str, Any] | None = None
    strategy_reason: str | None = None
    decision_source: str | None = None
    mutation_id: str | None = None
    mutation_family: str | None = None
    tactic_tag: str | None = None
    novelty_score: float | None = None
    judge_confidence: float | None = None
    judge_flags: list[str] = Field(default_factory=list)
    normalized_result: str | None = None
    normalized_severity: int | None = None
    attack_family: str | None = None
    mechanism: str | None = None
    example_incident: str | None = None
    input_channel: str | None = None
    expected_safe_behavior: str | None = None
    failure_signal: str | None = None
    recommended_mitigation: str | None = None
    judge_status: str | None = None
    mastermind: dict[str, Any] | None = None
    error: str | None = None
    capture_confidence: float | None = Field(default=None, ge=0, le=1)
    finding_state: FindingState | None = None
    hypothesis_id: str | None = None
    standards_mapping: list[str] = Field(default_factory=list)
    reproduction_count: int = 0
    provenance: dict[str, Any] = Field(default_factory=dict)
    purpose: Literal["coverage", "confirmation"] = "coverage"


class FindingEvidence(BaseModel):
    type: str
    source: str
    excerpt: str = ""
    start_index: int | None = None
    end_index: int | None = None
    confidence: float = Field(default=1.0, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExploitHypothesis(BaseModel):
    id: str
    run_id: str
    project_id: str = "local"
    source_lane_id: str
    attack_family: str
    mechanism: str = "unknown"
    preconditions: list[str] = Field(default_factory=list)
    affected_capability: str = "chat"
    evidence: list[FindingEvidence] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    target_fingerprint: str = ""
    safe_mutation_recipe: str
    expected_validation_signal: str
    quarantined: bool = False
    fanout_count: int = 0
    reproduction_count: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    id: str
    run_id: str
    project_id: str = "local"
    lane_id: str
    category: str
    title: str
    state: FindingState = FindingState.OBSERVED
    severity: int = Field(ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    evidence: list[FindingEvidence] = Field(default_factory=list)
    standards_mapping: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    hypothesis_id: str | None = None
    reproduction_count: int = 1
    provenance: dict[str, Any] = Field(default_factory=dict)
    reproduction_transcript: list[dict[str, str]] = Field(default_factory=list)
    attack_evolution: list[str] = Field(default_factory=list)
    impacted_capability: str = "chat"
    confirmation_status: str = "requires_reproduction"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReviewDecision(BaseModel):
    state: FindingState
    rationale: str = Field(min_length=1, max_length=2000)
    reviewer: str = Field(default="local-reviewer", max_length=120)


class FindingReview(BaseModel):
    id: int
    finding_id: str
    state: FindingState
    rationale: str
    reviewer: str
    created_at: datetime


class CoverageResult(BaseModel):
    profile: str
    attempted_categories: list[str] = Field(default_factory=list)
    skipped_categories: list[str] = Field(default_factory=list)
    supported_input_channels: list[str] = Field(default_factory=list)
    untested_input_channels: list[str] = Field(default_factory=list)
    browser_capture_failures: int = 0
    judge_degraded: int = 0
    complete: bool = True


class BrowserObservation(BaseModel):
    project_id: str = "local"
    target_url: str
    widget_fingerprint: str = ""
    route_pattern: str = "/"
    capture_confidence: float = Field(default=0, ge=0, le=1)
    selected_controls: dict[str, Any] = Field(default_factory=dict)
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    action_verification: dict[str, Any] = Field(default_factory=dict)
    response_candidates: list[dict[str, Any]] = Field(default_factory=list)
    timings_ms: dict[str, int] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    redacted_dom_excerpt: str = ""


class SelectorProfile(BaseModel):
    project_id: str = "local"
    origin: str
    route_pattern: str
    widget_fingerprint: str
    browser_version: str = "unknown"
    selectors: dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(default=0, ge=0, le=1)
    successes: int = 0
    failures: int = 0
    last_validated: datetime | None = None


class ReplayManifest(BaseModel):
    run_id: str
    project_id: str = "local"
    schema_version: str = "1.0"
    request: dict[str, Any]
    events: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CategorySummary(BaseModel):
    category: str
    total: int
    successes: int
    average_severity: float = 0.0
    critical_failures: int = 0


class RunReport(BaseModel):
    run_id: str
    status: RunStatus
    intensity: Intensity
    total_attacks: int
    successful_attacks: int
    success_rate: float
    total_critical_failures: int = 0
    categories: list[CategorySummary]
    lanes: list[LaneResult]
    coverage: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    schema_version: str = "2.0"
    confirmation_lanes: int = 0
    successful_confirmations: int = 0


class GenerateMitigationRequest(BaseModel):
    run_id: str
    vulnerable_system_prompt: str | None = None


class ApplyAndRerunRequest(BaseModel):
    run_id: str
    patched_system_prompt: str
    admin_url: str | None = None


class AnalyzeTargetRequest(BaseModel):
    url: str


class CreateProjectRequest(BaseModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9._-]+$", min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    retention_days: int = Field(default=30, ge=1, le=3650)


class UpdateProjectRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    retention_days: int | None = Field(default=None, ge=1, le=3650)


class BrowserPreflightRequest(BaseModel):
    url: str
    project_id: str = "local"
    selectors: dict[str, str] = Field(default_factory=dict)
    safe_probe: bool = True
    model_fallback: bool = False
    authorization_acknowledged: bool = False


INTENSITY_PROFILES: dict[Intensity, dict[str, int]] = {
    Intensity.LOW: {"attack_count": 3, "depth": 3},
    Intensity.MEDIUM: {"attack_count": 6, "depth": 5},
    Intensity.HIGH: {"attack_count": 12, "depth": 7},
}
