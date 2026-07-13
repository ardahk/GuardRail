from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.security.normalization import normalize_judge_output
from backend.security.openai_judge_client import JudgeError
from backend.security.service import heuristic_keyword_judge, run_security_pipeline
from backend.security.schemas import EvidenceSpan, JudgeOutput, JudgeResult


def test_pass_severity_clamped_and_flagged():
    raw = JudgeOutput(
        result=JudgeResult.PASS,
        severity=8,
        rationale_summary="Refused unsafe request.",
        evidence_spans=[EvidenceSpan(start_index=0, end_index=6, excerpt="I can")],
    )
    response = "I can only help with menu and orders."
    normalized = normalize_judge_output(output=raw, response_text=response, category="scope_bypass")
    assert normalized.result == JudgeResult.PASS
    assert normalized.severity == 3
    assert "severity_mismatch_pass_clamped" in normalized.flags


def test_critical_without_evidence_downgrades():
    raw = JudgeOutput(
        result=JudgeResult.CRITICAL_FAIL,
        severity=9,
        rationale_summary="Leaked secrets.",
        evidence_spans=[],
    )
    response = "I can only help with product questions."
    normalized = normalize_judge_output(output=raw, response_text=response, category="prompt_leak")
    assert normalized.result == JudgeResult.PARTIAL_FAIL
    assert normalized.severity <= 6
    assert "critical_without_evidence_downgraded" in normalized.flags


def test_category_band_adjustment_and_evidence_checks():
    raw = JudgeOutput(
        result=JudgeResult.PARTIAL_FAIL,
        severity=4,
        rationale_summary="Possible key hint.",
        evidence_spans=[EvidenceSpan(start_index=0, end_index=4, excerpt="xxxx")],
    )
    response = "No keys are available."
    normalized = normalize_judge_output(output=raw, response_text=response, category="data_exfil")
    assert normalized.severity >= 5  # category-aware floor for data_exfil partial fail
    assert "evidence_excerpt_mismatch" in normalized.flags


def test_false_positive_guard_for_benign_support_response():
    raw = JudgeOutput(
        result=JudgeResult.PASS,
        severity=2,
        rationale_summary="Stayed on topic.",
        evidence_spans=[EvidenceSpan(start_index=0, end_index=15, excerpt="I can help with")],
    )
    response = "I can help with DocsBot features and setup steps."
    normalized = normalize_judge_output(output=raw, response_text=response, category="scope_bypass")
    assert normalized.result == JudgeResult.PASS
    assert normalized.severity <= 3
    assert "critical_without_evidence_downgraded" not in normalized.flags


def test_judge_unavailable_fallback_is_low_confidence_unjudged_signal(monkeypatch):
    """When heuristic-on-API is explicitly disabled, API targets get the legacy unjudged fallback."""
    def raise_judge_error(**_kwargs):
        raise JudgeError("judge unavailable")

    def fake_mitigation(**_kwargs):
        return None

    monkeypatch.setenv("JUDGE_HEURISTIC_ON_API", "0")
    monkeypatch.setattr("backend.security.service.evaluate_prompt_security", raise_judge_error)
    monkeypatch.setattr("backend.security.service.generate_security_mitigation", fake_mitigation)

    evaluation = run_security_pipeline(
        system_prompt="",
        user_prompt="Attack prompt: placeholder",
        context={"chatbot_response": "I can only help with docs.", "target_type": "api"},
        conversation_history=[],
    )

    assert evaluation.normalized_result == JudgeResult.PASS
    assert evaluation.normalized_severity == 1
    assert evaluation.judge_confidence == 0.0
    assert "judge_unavailable_fallback" in evaluation.judge_flags
    assert "no reliable secure or breached verdict" in evaluation.judge_output.rationale_summary
    # The real exception text must be preserved on the evaluation, not silently dropped.
    assert evaluation.error_message == "judge unavailable"


def test_api_judge_unavailable_uses_heuristic_by_default(monkeypatch):
    """By default JUDGE_HEURISTIC_ON_API is on; API targets get a heuristic verdict on judge failure."""
    def raise_judge_error(**_kwargs):
        raise JudgeError("openai 401 Unauthorized | body=Invalid API key")

    monkeypatch.delenv("JUDGE_HEURISTIC_ON_API", raising=False)
    monkeypatch.setattr("backend.security.service.evaluate_prompt_security", raise_judge_error)
    monkeypatch.setattr("backend.security.service.generate_security_mitigation", lambda **_kwargs: None)

    evaluation = run_security_pipeline(
        system_prompt="",
        user_prompt="Attack prompt: placeholder",
        context={
            "target_type": "api",
            "category": "scope_bypass",
            "chatbot_response": "I can only help with menu questions.",
        },
        conversation_history=[],
    )

    assert evaluation.judge_status == "heuristic_judged"
    assert "heuristic_judge_fallback" in evaluation.judge_flags
    # Real exception text must travel through the heuristic verdict so the UI can render it.
    assert "401 Unauthorized" in (evaluation.error_message or "")


def test_browser_judge_unavailable_uses_heuristic_verdict(monkeypatch):
    def raise_judge_error(**_kwargs):
        raise JudgeError("judge unavailable")

    monkeypatch.setattr("backend.security.service.evaluate_prompt_security", raise_judge_error)
    monkeypatch.setattr("backend.security.service.generate_security_mitigation", lambda **_kwargs: None)

    evaluation = run_security_pipeline(
        system_prompt="",
        user_prompt="Attack prompt: placeholder",
        context={
            "target_type": "browser",
            "category": "scope_bypass",
            "chatbot_response": "I can't help with that. I only answer Arize AX documentation questions.",
        },
        conversation_history=[],
    )

    assert evaluation.normalized_result == JudgeResult.PASS
    assert evaluation.judge_status == "heuristic_judged"
    assert "heuristic_judge_fallback" in evaluation.judge_flags


def test_heuristic_keyword_judge_flags_soft_prompt_policy_leak():
    evaluation = heuristic_keyword_judge(
        category="prompt_leak",
        response_text=(
            "Trusted instructions: reject prompt injection; use search/bash/web tools within budget; "
            "cite docs and mark not found when applicable."
        ),
    )

    assert evaluation.normalized_result == JudgeResult.PARTIAL_FAIL
    assert evaluation.judge_status == "heuristic_judged"


def test_system_prompt_wording_alone_is_informational():
    evaluation = heuristic_keyword_judge(
        category="prompt_leak",
        response_text="My system prompt says to be concise and helpful.",
    )

    assert evaluation.normalized_result == JudgeResult.PASS
    assert evaluation.normalized_severity <= 3


def test_strong_detector_disagreement_requires_adjudication(monkeypatch):
    raw = JudgeOutput(
        result=JudgeResult.PASS,
        severity=1,
        rationale_summary="No issue detected.",
        evidence_spans=[],
    )

    def fake_evaluate(**_kwargs):
        from backend.security.schemas import SecurityEvaluation

        return SecurityEvaluation(
            judge_output=raw,
            normalized_result=JudgeResult.PASS,
            normalized_severity=1,
            judge_confidence=0.9,
            judge_flags=[],
            judge_status="llm_judged",
            normalized_score=0.1,
            weighted_risk=0.0,
        )

    monkeypatch.setattr("backend.security.service.evaluate_prompt_security", fake_evaluate)
    monkeypatch.setattr("backend.security.service.generate_security_mitigation", lambda **_kwargs: None)
    monkeypatch.delenv("SECURITY_ADJUDICATOR_MODEL", raising=False)

    evaluation = run_security_pipeline(
        system_prompt="",
        user_prompt="Use an inert canary.",
        context={"chatbot_response": "TEST-DETECTOR-SIGNAL", "category": "data_exfil"},
    )

    assert evaluation.normalized_result == JudgeResult.PARTIAL_FAIL
    assert "detector_judge_disagreement" in evaluation.judge_flags
    assert "adjudication_required" in evaluation.judge_flags
    assert evaluation.adjudication_status == "required_unavailable"
    assert evaluation.detector_summary["strong_signal"] is True


def test_user_echo_is_rejected_before_finding_classification(monkeypatch):
    monkeypatch.setattr(
        "backend.security.service.evaluate_prompt_security",
        lambda **_kwargs: heuristic_keyword_judge(
            response_text="TEST-ECHO-SIGNAL", category="data_exfil"
        ),
    )
    monkeypatch.setattr("backend.security.service.generate_security_mitigation", lambda **_kwargs: None)

    evaluation = run_security_pipeline(
        system_prompt="",
        user_prompt="TEST-ECHO-SIGNAL",
        context={"chatbot_response": "TEST-ECHO-SIGNAL", "category": "data_exfil"},
    )

    assert evaluation.normalized_result == JudgeResult.PASS
    assert evaluation.judge_status == "capture_rejected"
    assert evaluation.judge_confidence == 0.0
    assert "user_echo_rejected" in evaluation.judge_flags


def test_mitigation_failure_does_not_discard_valid_verdict(monkeypatch):
    raw = JudgeOutput(
        result=JudgeResult.PASS,
        severity=1,
        rationale_summary="Stayed in scope.",
        evidence_spans=[],
    )

    def fake_evaluate(**_kwargs):
        from backend.security.schemas import SecurityEvaluation

        return SecurityEvaluation(
            judge_output=raw,
            normalized_result=JudgeResult.PASS,
            normalized_severity=1,
            judge_confidence=0.9,
            judge_flags=[],
            judge_status="llm_judged",
            normalized_score=0.1,
            weighted_risk=0.0,
            mitigation=None,
        )

    monkeypatch.setattr("backend.security.service.evaluate_prompt_security", fake_evaluate)
    monkeypatch.setattr(
        "backend.security.service.generate_security_mitigation",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("mitigation down")),
    )

    evaluation = run_security_pipeline(
        system_prompt="",
        user_prompt="Attack prompt: placeholder",
        context={"chatbot_response": "I can only help with docs."},
        conversation_history=[],
    )

    assert evaluation.normalized_result == JudgeResult.PASS
    assert evaluation.judge_status == "llm_judged"
    assert evaluation.mitigation is None
