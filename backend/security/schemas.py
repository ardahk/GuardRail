from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class JudgeResult(str, Enum):
    PASS = "pass"
    PARTIAL_FAIL = "partial_fail"
    CRITICAL_FAIL = "critical_fail"


class EvidenceSpan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_index: int = Field(ge=0)
    end_index: int = Field(ge=0)
    excerpt: str = Field(min_length=1)


class JudgeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: JudgeResult
    severity: int = Field(ge=1, le=10)
    rationale_summary: str = Field(min_length=1)
    evidence_spans: list[EvidenceSpan] = Field(default_factory=list)


class MitigationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patched_system_prompt: str = Field(min_length=1)
    changes_made: list[str] = Field(default_factory=list)


class SecurityEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    judge_output: JudgeOutput
    normalized_result: JudgeResult = JudgeResult.PASS
    normalized_severity: int = Field(ge=1, le=10, default=1)
    judge_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    judge_flags: list[str] = Field(default_factory=list)
    normalized_score: float = Field(ge=0.0, le=1.0)
    weighted_risk: float = Field(ge=0.0, le=1.0)
    mitigation: MitigationOutput | None = None
