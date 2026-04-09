from __future__ import annotations

from typing import Any

from .config import SecurityModelConfig
from .gemini_client import GeminiJudgeClient, GeminiJudgeError
from .mitigation import build_mitigation
from .normalization import normalize_judge_output
from .scoring import aggregate_risk_scores, normalized_severity, weighted_risk_score
from .schemas import JudgeOutput, JudgeResult, MitigationOutput, SecurityEvaluation


def evaluate_prompt_security(
    *,
    system_prompt: str,
    user_prompt: str,
    context: dict[str, Any] | None = None,
    config: SecurityModelConfig | None = None,
    conversation_history: list[dict[str, str]] | None = None,
) -> SecurityEvaluation:
    effective_config = config or SecurityModelConfig.from_env()
    client = GeminiJudgeClient(effective_config)
    client.assert_model_available()
    judge_output = client.judge(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        context=context,
        conversation_history=conversation_history,
    )
    normalized = normalize_judge_output(
        output=judge_output,
        response_text=(context or {}).get("chatbot_response", ""),
        category=(context or {}).get("category", ""),
    )
    return SecurityEvaluation(
        judge_output=judge_output,
        normalized_result=normalized.result,
        normalized_severity=normalized.severity,
        judge_confidence=normalized.confidence,
        judge_flags=normalized.flags,
        normalized_score=normalized_severity(normalized.severity),
        weighted_risk=weighted_risk_score(
            JudgeOutput(
                result=normalized.result,
                severity=normalized.severity,
                rationale_summary=judge_output.rationale_summary,
                evidence_spans=normalized.evidence_spans,
            )
        ),
        mitigation=None,
    )


def generate_security_mitigation(
    *,
    system_prompt: str,
    breach_cases: list[dict],
) -> MitigationOutput:
    config = SecurityModelConfig.from_env()
    client = GeminiJudgeClient(config)
    client.assert_model_available()
    try:
        return client.mitigate(
            vulnerable_system_prompt=system_prompt,
            breach_cases=breach_cases,
        )
    except GeminiJudgeError:
        return build_mitigation(system_prompt=system_prompt, breach_cases=breach_cases)


def run_security_pipeline(
    *,
    system_prompt: str,
    user_prompt: str,
    context: dict[str, Any] | None = None,
    config: SecurityModelConfig | None = None,
    conversation_history: list[dict[str, str]] | None = None,
) -> SecurityEvaluation:
    try:
        evaluation = evaluate_prompt_security(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context=context,
            config=config,
            conversation_history=conversation_history,
        )
    except GeminiJudgeError:
        fallback = JudgeOutput(
            result=JudgeResult.PASS,
            severity=1,
            rationale_summary="Judge unavailable; defaulted to safe pass classification.",
            evidence_spans=[],
        )
        evaluation = SecurityEvaluation(
            judge_output=fallback,
            normalized_result=JudgeResult.PASS,
            normalized_severity=1,
            judge_confidence=0.1,
            judge_flags=["judge_unavailable_fallback"],
            normalized_score=normalized_severity(1),
            weighted_risk=0.0,
            mitigation=None,
        )
    mitigation = generate_security_mitigation(
        system_prompt=system_prompt,
        breach_cases=[
            {
                "judge_result": evaluation.normalized_result,
                "severity": evaluation.normalized_severity,
                "rationale": evaluation.judge_output.rationale_summary,
                "attack_prompts": [user_prompt],
                "responses": [],
                "category": "unknown",
                "lane_id": "pipeline",
            }
        ],
    )
    return evaluation.model_copy(update={"mitigation": mitigation})


def aggregate_security_evaluations(evaluations: list[SecurityEvaluation]) -> float:
    return aggregate_risk_scores([item.judge_output for item in evaluations])
