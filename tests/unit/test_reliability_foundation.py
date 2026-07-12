from __future__ import annotations

import asyncio

from backend.core.blackboard import RunBlackboard
from backend.core.models import (
    CreateRunRequest,
    Finding,
    FindingEvidence,
    FindingState,
    Intensity,
    LaneResult,
    ReviewDecision,
    RunStatus,
    TargetConfig,
)
from backend.core.persistence import DurableRepository
from backend.core.reporting import aggregate_report, to_sarif
from backend.core.store import RunRecord, RunStore
from backend.security.evidence import deterministic_evidence, initial_finding_state, standards_for


def _request(project_id: str = "local") -> CreateRunRequest:
    return CreateRunRequest(
        target=TargetConfig(base_url="http://fixture", api_key="x", model="fixture"),
        project_id=project_id,
        authorization_acknowledged=True,
    )


def test_deterministic_evidence_detects_canary_and_rejects_user_echo():
    evidence = deterministic_evidence(
        "TEST-OVERRIDE-SUCCESS",
        user_prompt="TEST-OVERRIDE-SUCCESS",
        capture_confidence=0.9,
    )
    kinds = {item.type for item in evidence}
    assert {"canary_marker", "user_echo", "browser_capture_confidence"} <= kinds
    assert "OWASP-LLM01:2025" in standards_for("scope_bypass", evidence)


def test_high_severity_finding_enters_review_queue():
    state = initial_finding_state(
        result="critical_fail",
        severity=9,
        confidence=0.95,
        evidence=[FindingEvidence(type="canary_marker", source="response", excerpt="TEST-X")],
        judge_status="llm_judged",
        review_policy="risk_based",
    )
    assert state == FindingState.PENDING


def test_durable_store_restores_run_and_isolates_projects(tmp_path):
    repo = DurableRepository(str(tmp_path / "guardrail.db"))
    repo.create_project("project-a", "A")
    async def scenario():
        store = RunStore(repo)
        rec = await store.create_run(_request("project-a"))
        restored = RunStore(repo)
        return rec, await restored.get_run(rec.id)

    rec, loaded = asyncio.run(scenario())
    assert loaded is not None
    assert loaded.request.project_id == "project-a"


def test_review_updates_finding_state(tmp_path):
    repo = DurableRepository(str(tmp_path / "guardrail.db"))
    finding = Finding(
        id="finding-1",
        run_id="run-1",
        lane_id="lane-1",
        category="prompt_leak",
        title="Prompt leak",
        state=FindingState.PENDING,
        severity=8,
        confidence=0.8,
    )
    repo.save_finding(finding)
    updated = repo.review_finding(
        finding.id,
        ReviewDecision(state=FindingState.CONFIRMED, rationale="Reproduced with inert canary."),
    )
    assert updated is not None
    assert updated.state == FindingState.CONFIRMED


def test_blackboard_quarantines_low_confidence_and_bounds_fanout():
    async def scenario():
        board = RunBlackboard()
        item = await board.publish(
            run_id="run",
            project_id="local",
            source_lane_id="lane-1",
            attack_family="direct_override",
            mechanism="instruction_override",
            preconditions=[],
            evidence=[],
            confidence=0.4,
            target_fingerprint="fixture",
            safe_mutation_recipe="Use inert variants.",
            expected_validation_signal="TEST-SIGNAL",
            quarantined=True,
        )
        assert item.quarantined
        assert await board.compatible(
            run_id="run", lane_id="lane-2", attack_family="direct_override",
            mechanism="instruction_override", fanout_limit=3,
        ) == []

        safe = await board.publish(
            run_id="run",
            project_id="local",
            source_lane_id="lane-1",
            attack_family="direct_override",
            mechanism="instruction_override",
            preconditions=[],
            evidence=[],
            confidence=0.9,
            target_fingerprint="fixture",
            safe_mutation_recipe="Use inert variants.",
            expected_validation_signal="TEST-SIGNAL",
            quarantined=False,
        )
        consumed = await board.compatible(
            run_id="run", lane_id="lane-2", attack_family="other",
            mechanism="instruction_override", fanout_limit=1,
        )
        assert consumed[0].id == safe.id
        assert consumed[0].fanout_count == 1

    asyncio.run(scenario())


def test_degraded_lane_is_reported_as_incomplete_coverage_and_sarif_exports_findings():
    request = _request()
    run = RunRecord(id="run", request=request, intensity=Intensity.LOW, status=RunStatus.COMPLETED)
    report = aggregate_report(
        run,
        [
            LaneResult(
                lane_id="lane-1", attack_id="a", category="prompt_leak",
                success=False, attempts=1, judge_status="unjudged", error="judge unavailable",
            )
        ],
    )
    assert report.coverage["complete"] is False
    assert report.coverage["judge_degraded"] == 1

    sarif = to_sarif({
        "findings": [{
            "id": "f", "title": "Inert canary disclosure", "severity": 8,
            "state": "pending", "confidence": 0.8,
            "standards_mapping": ["OWASP-LLM02:2025"], "remediation": ["Redact output."],
        }]
    })
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "OWASP-LLM02:2025"
