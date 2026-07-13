from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

import backend.main as main
from backend.core.models import (
    CreateRunRequest,
    ExploitHypothesis,
    Finding,
    FindingState,
    ReviewDecision,
    TargetConfig,
)
from backend.core.persistence import DurableRepository
from backend.core.store import RunStore


def _client(monkeypatch, tmp_path):
    repository = DurableRepository(str(tmp_path / "guardrail.db"))
    store = RunStore(repository)
    monkeypatch.setattr(main, "_repository", repository)
    monkeypatch.setattr(main, "_store", store)
    monkeypatch.setattr(main._orchestrator, "store", store)
    return TestClient(main.app), repository, store


def test_project_run_review_replay_and_export_contract(monkeypatch, tmp_path):
    client, repository, store = _client(monkeypatch, tmp_path)
    assert client.post(
        "/projects",
        json={"id": "project-a", "name": "Project A", "retention_days": 30},
    ).status_code == 200
    updated_project = client.patch(
        "/projects/project-a", json={"retention_days": 45}
    )
    assert updated_project.status_code == 200
    assert updated_project.json()["retention_days"] == 45

    created = client.post(
        "/runs",
        json={
            "target": {"base_url": "http://fixture", "api_key": "x", "model": "fixture"},
            "project_id": "project-a",
            "authorization_acknowledged": True,
            "intensity": "low",
        },
    )
    assert created.status_code == 200
    run_id = created.json()["id"]

    finding = Finding(
        id="finding-a",
        run_id=run_id,
        project_id="project-a",
        lane_id="lane-1",
        category="prompt_leak",
        title="Inert canary disclosed",
        state=FindingState.PENDING,
        severity=8,
        confidence=0.91,
        standards_mapping=["OWASP-LLM07:2025"],
    )
    repository.save_finding(finding)
    hypothesis = ExploitHypothesis(
        id="hypothesis-a", run_id=run_id, project_id="project-a",
        source_lane_id="lane-1", attack_family="prompt_leak",
        confidence=0.9, safe_mutation_recipe="Use an inert variant.",
        expected_validation_signal="TEST-X",
    )
    repository.save_hypothesis(hypothesis)
    knowledge = client.get(f"/projects/project-a/hypotheses?run_id={run_id}")
    assert knowledge.status_code == 200
    assert knowledge.json()["hypotheses"][0]["id"] == hypothesis.id

    detail = client.get(f"/findings/{finding.id}")
    assert detail.status_code == 200
    assert detail.json()["reviews"] == []

    reviewed = client.post(
        f"/findings/{finding.id}/review",
        json={"state": "confirmed", "rationale": "Reproduced with inert marker.", "reviewer": "analyst"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["state"] == "confirmed"
    history = client.get(f"/findings/{finding.id}/reviews").json()
    assert history["count"] == 1
    assert history["reviews"][0]["reviewer"] == "analyst"

    report = client.get(f"/runs/{run_id}/report").json()
    assert report["findings"][0]["state"] == "confirmed"
    replay = client.get(f"/runs/{run_id}/replay")
    assert replay.status_code == 200
    assert replay.json()["project_id"] == "project-a"
    assert replay.json()["findings"][0]["id"] == finding.id

    exported = client.get(f"/runs/{run_id}/export?format=sarif")
    assert exported.status_code == 200
    assert exported.json()["version"] == "2.1.0"
    json_export = client.get(f"/runs/{run_id}/export?format=json").json()
    assert json_export["schema_version"] == "2.1"
    assert json_export["hypotheses"][0]["id"] == hypothesis.id
    assert json_export["project_id"] == "project-a"

    candidate = client.post(
        "/runs",
        json={
            "target": {"base_url": "http://fixture", "api_key": "x", "model": "fixture"},
            "project_id": "project-a",
            "authorization_acknowledged": True,
            "intensity": "low",
        },
    ).json()["id"]
    comparison = client.get(
        f"/runs/compare?baseline_run_id={run_id}&candidate_run_id={candidate}"
    )
    assert comparison.status_code == 200
    assert comparison.json()["comparable"] is False
    assert "baseline_incomplete" in comparison.json()["comparability_reasons"]
    assert "judge_provenance_missing" in comparison.json()["comparability_reasons"]

    assert client.post(
        "/runs",
        json={
            "target": {"base_url": "http://fixture", "api_key": "x", "model": "fixture"},
            "project_id": "missing-project",
        },
    ).status_code == 404

    restored = RunStore(repository)
    assert asyncio.run(restored.get_run(run_id)) is not None


def test_project_data_deletion_removes_runs_findings_and_reviews(monkeypatch, tmp_path):
    client, repository, store = _client(monkeypatch, tmp_path)
    repository.create_project("delete-me", "Delete Me")
    run = asyncio.run(store.create_run(CreateRunRequest(
        target=TargetConfig(base_url="http://fixture", api_key="x", model="fixture"),
        project_id="delete-me",
    )))
    finding = Finding(
        id="finding-delete", run_id=run.id, project_id="delete-me", lane_id="lane-1",
        category="scope_bypass", title="Delete", state=FindingState.PENDING,
        severity=4, confidence=0.7,
    )
    repository.save_finding(finding)
    repository.review_finding(
        finding.id,
        ReviewDecision(state=FindingState.REJECTED, rationale="False positive"),
    )
    response = client.delete("/projects/delete-me/data")
    assert response.status_code == 200
    assert client.get(f"/runs/{run.id}/report").status_code == 404
    assert repository.get_finding(finding.id) is None
    assert repository.list_finding_reviews(finding.id) == []


def test_browser_runs_require_authorization_and_cannot_apply_prompt(monkeypatch, tmp_path):
    client, _repository, _store = _client(monkeypatch, tmp_path)
    payload = {
        "target": {
            "base_url": "http://127.0.0.1:7071",
            "api_key": "demo-key",
            "model": "browser",
            "target_type": "browser",
            "playwright_target_url": "http://127.0.0.1:7080/inline",
        },
        "project_id": "local",
    }
    denied = client.post("/runs", json=payload)
    assert denied.status_code == 400
    assert "authorized" in denied.json()["detail"]

    payload["authorization_acknowledged"] = True
    created = client.post("/runs", json=payload)
    assert created.status_code == 200
    rerun = client.post(
        "/mitigations/apply-and-rerun",
        json={"run_id": created.json()["id"], "patched_system_prompt": "patched"},
    )
    assert rerun.status_code == 400
    assert "browser targets" in rerun.json()["detail"]


def test_prompt_sync_failure_blocks_run_start(monkeypatch, tmp_path):
    client, _repository, store = _client(monkeypatch, tmp_path)

    class FailingClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, **kwargs):
            import httpx
            return httpx.Response(503, request=httpx.Request("POST", url))

    monkeypatch.setattr(main.httpx, "AsyncClient", FailingClient)
    created = client.post(
        "/runs",
        json={
            "target": {
                "base_url": "http://fixture",
                "api_key": "x",
                "model": "fixture",
                "admin_url": "http://127.0.0.1:7070/admin/prompt",
            },
            "system_prompt": "Known prompt",
            "project_id": "local",
        },
    ).json()
    started = client.post(f"/runs/{created['id']}/start")
    assert started.status_code == 502
    run = asyncio.run(store.get_run(created["id"]))
    assert run is not None and run.status.value == "created"
    assert any(event.type == "prompt_sync_failed" for event in run.events)
