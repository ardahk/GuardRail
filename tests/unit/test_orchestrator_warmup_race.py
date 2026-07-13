from __future__ import annotations

import asyncio

from backend.core.models import (
    AttackDefinition,
    CreateRunRequest,
    Intensity,
    LaneResult,
    RunStatus,
    TargetConfig,
)
from backend.core.orchestrator import RunOrchestrator
from backend.core.store import RunStore


def test_browser_warmup_ready_event_does_not_cancel_warmup_lane():
    async def _run() -> None:
        store = RunStore()
        attacks = [
            AttackDefinition(
                id="a1",
                category="prompt_leak",
                prompt_template="x",
                severity_weight=1.0,
                success_criteria=["x"],
            ),
            AttackDefinition(
                id="a2",
                category="scope_bypass",
                prompt_template="x",
                severity_weight=0.9,
                success_criteria=["x"],
            ),
        ]
        orchestrator = RunOrchestrator(store, attacks)

        async def fake_run_lane(
            run_id: str,
            adapter,
            lane_idx: int,
            attack: AttackDefinition,
            depth: int,
            ready_event: asyncio.Event | None = None,
            playbook_entries=None,
            target_domain: str = "",
        ) -> LaneResult:
            # Recreate the exact race:
            # lane-1 signals readiness quickly, but still needs to complete later.
            if ready_event is not None and not ready_event.is_set():
                ready_event.set()
                await asyncio.sleep(0.05)
            else:
                await asyncio.sleep(0.01)
            return LaneResult(
                lane_id=f"lane-{lane_idx}",
                attack_id=attack.id,
                category=attack.category,
                success=False,
                attempts=1,
                responses=["ok"],
                judge_result="pass",
                severity=1,
            )

        orchestrator._run_lane = fake_run_lane  # type: ignore[method-assign]

        req = CreateRunRequest(
            target=TargetConfig(
                base_url="http://127.0.0.1:7071/v1/chat/completions",
                api_key="dummy",
                model="browser-playwright",
                target_type="browser",
            ),
            intensity=Intensity.MEDIUM,
        )
        rec = await store.create_run(req)
        await orchestrator.execute_run(rec.id)
        out = await store.get_run(rec.id)
        assert out is not None
        assert out.status == RunStatus.COMPLETED
        assert len(out.lanes) == 2
        assert any(event.type == "warmup_succeeded" for event in out.events)
        assert all(event.payload.get("reason") != "cancelled" for event in out.events if event.type == "run_failed")

    asyncio.run(_run())


def test_browser_warmup_timeout_marks_run_failed(monkeypatch):
    async def _run() -> None:
        store = RunStore()
        attack = AttackDefinition(
            id="a1",
            category="prompt_leak",
            prompt_template="x",
            severity_weight=1.0,
            success_criteria=["x"],
        )
        orchestrator = RunOrchestrator(store, [attack])

        async def never_ready(*_args, **_kwargs) -> LaneResult:
            await asyncio.sleep(60)
            raise AssertionError("warmup lane should have been cancelled")

        orchestrator._run_lane = never_ready  # type: ignore[method-assign]
        monkeypatch.setenv("BROWSER_WARMUP_TIMEOUT_MS", "10")
        monkeypatch.setattr(
            "backend.core.orchestrator.judge_health_check",
            lambda: {"ok": True, "provider": "xai", "model": "grok-4.3", "latency_ms": 1},
        )

        req = CreateRunRequest(
            target=TargetConfig(
                base_url="http://127.0.0.1:7071",
                api_key="dummy",
                model="browser",
                target_type="browser",
            ),
            intensity=Intensity.LOW,
        )
        rec = await store.create_run(req)
        await orchestrator.execute_run(rec.id)

        out = await store.get_run(rec.id)
        assert out is not None
        assert out.status == RunStatus.FAILED
        failures = [event for event in out.events if event.type == "run_failed"]
        assert len(failures) == 1
        assert "warmup timed out" in failures[0].payload["reason"].lower()

    asyncio.run(_run())
