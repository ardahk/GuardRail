from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .models import AttackDefinition, CreateRunRequest, Intensity, LaneResult, RunEvent, RunStatus
from .persistence import DurableRepository


@dataclass
class RunRecord:
    id: str
    request: CreateRunRequest
    intensity: Intensity
    status: RunStatus = RunStatus.CREATED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    attacks: list[AttackDefinition] = field(default_factory=list)
    lanes: list[LaneResult] = field(default_factory=list)
    events: list[RunEvent] = field(default_factory=list)
    report: dict[str, Any] | None = None


class RunStore:
    def __init__(self, repository: DurableRepository | None = None):
        self._runs: dict[str, RunRecord] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}
        self._lock = asyncio.Lock()
        self.repository = repository
        if repository is not None:
            for payload in repository.load_run_snapshots():
                try:
                    rec = self._deserialize(payload)
                    if rec.status == RunStatus.RUNNING:
                        rec.status = RunStatus.FAILED
                        rec.finished_at = datetime.now(timezone.utc)
                        rec.events.append(
                            RunEvent(
                                run_id=rec.id,
                                type="run_recovered",
                                payload={
                                    "reason": "Process restarted while run was active; coverage is incomplete."
                                },
                            )
                        )
                    self._runs[rec.id] = rec
                    self._persist(rec)
                except Exception:
                    continue

    @staticmethod
    def _serialize(rec: RunRecord) -> dict[str, Any]:
        return {
            "id": rec.id,
            "request": rec.request.model_dump(mode="json"),
            "intensity": rec.intensity.value,
            "status": rec.status.value,
            "created_at": rec.created_at.isoformat(),
            "started_at": rec.started_at.isoformat() if rec.started_at else None,
            "finished_at": rec.finished_at.isoformat() if rec.finished_at else None,
            "attacks": [item.model_dump(mode="json") for item in rec.attacks],
            "lanes": [item.model_dump(mode="json") for item in rec.lanes],
            "events": [item.model_dump(mode="json") for item in rec.events],
            "report": rec.report,
        }

    @staticmethod
    def _deserialize(payload: dict[str, Any]) -> RunRecord:
        def dt(value: str | None) -> datetime | None:
            return datetime.fromisoformat(value) if value else None

        return RunRecord(
            id=str(payload["id"]),
            request=CreateRunRequest.model_validate(payload["request"]),
            intensity=Intensity(payload["intensity"]),
            status=RunStatus(payload["status"]),
            created_at=dt(payload.get("created_at")) or datetime.now(timezone.utc),
            started_at=dt(payload.get("started_at")),
            finished_at=dt(payload.get("finished_at")),
            attacks=[AttackDefinition.model_validate(item) for item in payload.get("attacks", [])],
            lanes=[LaneResult.model_validate(item) for item in payload.get("lanes", [])],
            events=[RunEvent.model_validate(item) for item in payload.get("events", [])],
            report=payload.get("report"),
        )

    def _persist(self, rec: RunRecord) -> None:
        if self.repository is not None:
            self.repository.save_run_snapshot(
                rec.id,
                rec.request.project_id,
                rec.status.value,
                self._serialize(rec),
            )

    async def create_run(self, req: CreateRunRequest) -> RunRecord:
        async with self._lock:
            run_id = str(uuid4())
            rec = RunRecord(id=run_id, request=req, intensity=req.intensity)
            self._runs[run_id] = rec
            self._persist(rec)
            return rec

    async def get_run(self, run_id: str) -> RunRecord | None:
        async with self._lock:
            return self._runs.get(run_id)

    async def save_run(self, rec: RunRecord) -> None:
        async with self._lock:
            self._runs[rec.id] = rec
            self._persist(rec)

    async def set_task(self, run_id: str, task: asyncio.Task[None]) -> None:
        async with self._lock:
            self._tasks[run_id] = task

    async def get_task(self, run_id: str) -> asyncio.Task[None] | None:
        async with self._lock:
            return self._tasks.get(run_id)

    async def clear_task(self, run_id: str) -> None:
        async with self._lock:
            self._tasks.pop(run_id, None)

    async def append_event(self, run_id: str, event_type: str, payload: dict[str, Any] | None = None) -> None:
        payload = payload or {}
        event = RunEvent(run_id=run_id, type=event_type, payload=payload)

        async with self._lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return
            rec.events.append(event)
            self._persist(rec)
            subscribers = list(self._subscribers.get(run_id, set()))

        for q in subscribers:
            try:
                q.put_nowait(event.model_dump(mode="json"))
            except asyncio.QueueFull:
                continue

    async def subscribe(self, run_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        async with self._lock:
            self._subscribers.setdefault(run_id, set()).add(queue)
        return queue

    async def unsubscribe(self, run_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            if run_id not in self._subscribers:
                return
            self._subscribers[run_id].discard(queue)
            if not self._subscribers[run_id]:
                self._subscribers.pop(run_id, None)

    async def clear_project_runs(self, project_id: str) -> int:
        async with self._lock:
            run_ids = [
                run_id for run_id, rec in self._runs.items()
                if rec.request.project_id == project_id
            ]
            for run_id in run_ids:
                task = self._tasks.pop(run_id, None)
                if task and not task.done():
                    task.cancel()
                self._runs.pop(run_id, None)
                self._subscribers.pop(run_id, None)
            return len(run_ids)
