from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from backend.core.blackboard import RunBlackboard
from backend.core.models import (
    AttackDefinition,
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
from backend.core.orchestrator import RunOrchestrator
from backend.core.persistence import DurableRepository
from backend.core.reporting import aggregate_report, compare_runs, to_sarif
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


def test_sensitive_evidence_is_redacted_but_hash_and_offsets_are_preserved():
    response = "credential: sk-ABCDEFGHIJKLMNOPQRSTUV"
    evidence = deterministic_evidence(response)
    secret = next(item for item in evidence if item.type == "secret_pattern")
    assert secret.excerpt == "[REDACTED_SECRET]"
    assert secret.start_index is not None and secret.end_index is not None
    assert secret.metadata["redacted"] is True
    assert len(secret.metadata["evidence_hash"]) == 64


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


def test_blackboard_requires_mechanism_or_family_and_same_target():
    async def scenario():
        board = RunBlackboard()
        item = await board.publish(
            run_id="run", project_id="local", source_lane_id="lane-1",
            attack_family="prompt_leak", mechanism="instruction_disclosure",
            preconditions=[], evidence=[], confidence=0.9, target_fingerprint="widget-a",
            safe_mutation_recipe="Use an inert variation.", expected_validation_signal="TEST-X",
            quarantined=False,
        )
        assert await board.compatible(
            run_id="run", lane_id="lane-2", attack_family="data_exfil",
            mechanism="retrieval_abuse", fanout_limit=3, target_fingerprint="widget-a",
        ) == []
        assert await board.compatible(
            run_id="run", lane_id="lane-2", attack_family="prompt_leak",
            mechanism="other", fanout_limit=3, target_fingerprint="widget-b",
        ) == []
        matched = await board.compatible(
            run_id="run", lane_id="lane-2", attack_family="prompt_leak",
            mechanism="other", fanout_limit=3, target_fingerprint="widget-a",
            preferred_hypothesis_id=item.id,
        )
        assert matched[0].id == item.id

    asyncio.run(scenario())


def test_orchestrator_schedules_bounded_confirmation_lane(monkeypatch):
    attack = AttackDefinition(
        id="a1", category="prompt_leak", prompt_template="inert",
        severity_weight=1.0, success_criteria=["TEST-X"],
        attack_family="prompt_leak", mechanism="instruction_disclosure",
    )

    async def scenario():
        store = RunStore()
        run = await store.create_run(_request())
        orchestrator = RunOrchestrator(store, [attack])

        async def fake_lane(
            run_id, _adapter, lane_idx, selected_attack, _depth, _semaphore,
            **kwargs,
        ):
            if lane_idx == 1:
                await orchestrator.blackboard.publish(
                    run_id=run_id, project_id="local", source_lane_id="lane-1",
                    attack_family="prompt_leak", mechanism="instruction_disclosure",
                    preconditions=[], evidence=[], confidence=0.9, target_fingerprint="fixture",
                    safe_mutation_recipe="Use an inert variation.", expected_validation_signal="TEST-X",
                    quarantined=False,
                )
            return LaneResult(
                lane_id=f"lane-{lane_idx}", attack_id=selected_attack.id,
                category=selected_attack.category, success=bool(kwargs.get("seed_hypothesis_id")),
                attempts=1, judge_result="partial_fail" if kwargs.get("seed_hypothesis_id") else "pass",
                severity=5 if kwargs.get("seed_hypothesis_id") else 1,
                purpose="confirmation" if kwargs.get("seed_hypothesis_id") else "coverage",
            )

        monkeypatch.setattr(orchestrator, "_run_lane_with_limit", fake_lane)
        monkeypatch.setattr("backend.core.orchestrator.judge_health_check", lambda: {"ok": True})
        await orchestrator.execute_run(run.id)
        completed = await store.get_run(run.id)
        return completed

    completed = asyncio.run(scenario())
    assert completed is not None
    assert len(completed.lanes) == 2
    scheduled = [event for event in completed.events if event.type == "confirmation_lanes_scheduled"]
    assert scheduled[0].payload["count"] == 1
    assert completed.report["total_attacks"] == 1
    assert completed.report["successful_attacks"] == 0
    assert completed.report["confirmation_lanes"] == 1


def test_retention_removes_expired_project_artifacts(tmp_path):
    repo = DurableRepository(str(tmp_path / "retention.db"))
    repo.create_project("short", "Short retention", retention_days=1)
    repo.save_run_snapshot("old", "short", "completed", {"id": "old"})
    old = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    with repo._connect() as conn:
        conn.execute("UPDATE run_snapshots SET updated_at = ? WHERE id = 'old'", (old,))
        conn.commit()
    deleted = repo.enforce_retention("short")
    assert deleted["runs"] == 1
    assert deleted["expired_run_ids"] == ["old"]


def test_run_comparison_requires_identical_corpus_and_versions():
    baseline = RunRecord(id="before", request=_request(), intensity=Intensity.LOW)
    candidate = RunRecord(id="after", request=_request(), intensity=Intensity.LOW)
    baseline.status = candidate.status = RunStatus.COMPLETED
    baseline.attacks = candidate.attacks = [
        AttackDefinition(
            id="a1", category="prompt_leak", prompt_template="x",
            severity_weight=1, success_criteria=["TEST-X"],
        )
    ]
    lane = LaneResult(
        lane_id="lane-1", attack_id="a1", category="prompt_leak",
        success=False, attempts=1,
        provenance={"judge_model": "judge-a", "judge_prompt_version": "v1"},
    )
    baseline.lanes = [lane]
    candidate.lanes = [lane]
    baseline.report = {"successful_attacks": 1, "success_rate": 1.0, "total_critical_failures": 1, "coverage": {"complete": True}}
    candidate.report = {"successful_attacks": 0, "success_rate": 0.0, "total_critical_failures": 0, "coverage": {"complete": True}}
    comparison = compare_runs(baseline, candidate)
    assert comparison["comparable"] is True
    assert comparison["delta"] == {"successful_attacks": -1, "success_rate": -1.0, "critical_failures": -1}


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
