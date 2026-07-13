from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

import backend.main as main
from backend.core.models import CreateRunRequest, LaneResult, RunStatus, TargetConfig
from backend.core.persistence import DurableRepository
from backend.core.reporting import aggregate_report
from backend.core.store import RunStore
from backend.security.schemas import MitigationOutput


def test_mitigation_generation_uses_all_breached_lanes(monkeypatch, tmp_path):
    repository = DurableRepository(str(tmp_path / "guardrail.db"))
    store = RunStore(repository)
    monkeypatch.setattr(main, "_repository", repository)
    monkeypatch.setattr(main, "_store", store)
    monkeypatch.setattr(main._orchestrator, "store", store)

    request = CreateRunRequest(
        target=TargetConfig(base_url="http://fixture", api_key="x", model="fixture"),
        system_prompt="Original safe-policy prompt.",
    )
    run = asyncio.run(store.create_run(request))
    run.status = RunStatus.COMPLETED
    run.lanes = [
        LaneResult(
            lane_id="lane-1", attack_id="a", category="prompt_leak", success=True,
            attempts=1, responses=["TEST-SIGNAL-A"], judge_result="partial_fail", severity=6,
            rationale_summary="Canary disclosed.",
        ),
        LaneResult(
            lane_id="lane-2", attack_id="b", category="scope_bypass", success=True,
            attempts=1, responses=["TEST-SIGNAL-B"], judge_result="critical_fail", severity=8,
            rationale_summary="Boundary bypassed.",
        ),
    ]
    run.report = aggregate_report(run, run.lanes).model_dump(mode="json")
    asyncio.run(store.save_run(run))
    asyncio.run(store.append_event(run.id, "attack_sent", {"lane_id": "lane-1", "prompt": "probe-a"}))
    asyncio.run(store.append_event(run.id, "attack_sent", {"lane_id": "lane-2", "prompt": "probe-b"}))

    captured = {}
    def fake_mitigation(*, system_prompt, breach_cases):
        captured["system_prompt"] = system_prompt
        captured["breach_cases"] = breach_cases
        return MitigationOutput(
            patched_system_prompt=f"{system_prompt}\nEnforce authorization outside the model.",
            changes_made=["Added deterministic authorization requirement"],
        )

    monkeypatch.setattr(main, "generate_security_mitigation", fake_mitigation)
    response = TestClient(main.app).post(
        "/mitigations/generate",
        json={"run_id": run.id},
    )
    assert response.status_code == 200
    assert len(captured["breach_cases"]) == 2
    assert {case["lane_id"] for case in captured["breach_cases"]} == {"lane-1", "lane-2"}
    assert "authorization" in response.json()["patched_system_prompt"].lower()
