from __future__ import annotations

from typing import Any

from .config import SecurityModelConfig
from .gemini_client import GeminiJudgeClient, GeminiJudgeError
from .mitigation import build_mitigation
from .scoring import aggregate_risk_scores, normalized_severity, weighted_risk_score
from .schemas import JudgeOutput, MitigationOutput, SecurityEvaluation


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
    return SecurityEvaluation(
        judge_output=judge_output,
        normalized_score=normalized_severity(judge_output.severity),
        weighted_risk=weighted_risk_score(judge_output),
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
    evaluation = evaluate_prompt_security(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        context=context,
        config=config,
        conversation_history=conversation_history,
    )
    mitigation = generate_security_mitigation(
        system_prompt=system_prompt,
        breach_cases=[
            {
                "judge_result": evaluation.judge_output.result,
                "severity": evaluation.judge_output.severity,
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
