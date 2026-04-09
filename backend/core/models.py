from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

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


class CreateRunRequest(BaseModel):
    target: TargetConfig
    intensity: Intensity = Intensity.MEDIUM
    system_prompt: str = ""
    max_turns: int | None = Field(default=None, ge=1)
    attack_categories: list[str] | None = None
    auto_analyzed_context: dict[str, Any] | None = None
    director_enabled: bool = True


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
    error: str | None = None


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


class GenerateMitigationRequest(BaseModel):
    run_id: str
    vulnerable_system_prompt: str | None = None


class ApplyAndRerunRequest(BaseModel):
    run_id: str
    patched_system_prompt: str
    admin_url: str | None = None


class AnalyzeTargetRequest(BaseModel):
    url: str


INTENSITY_PROFILES: dict[Intensity, dict[str, int]] = {
    Intensity.LOW: {"attack_count": 3, "depth": 3},
    Intensity.MEDIUM: {"attack_count": 6, "depth": 4},
    Intensity.HIGH: {"attack_count": 12, "depth": 5},
}
