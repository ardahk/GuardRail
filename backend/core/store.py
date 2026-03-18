from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .models import AttackDefinition, CreateRunRequest, Intensity, LaneResult, RunEvent, RunStatus


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
    def __init__(self):
        self._runs: dict[str, RunRecord] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}
        self._lock = asyncio.Lock()

    async def create_run(self, req: CreateRunRequest) -> RunRecord:
        async with self._lock:
            run_id = str(uuid4())
            rec = RunRecord(id=run_id, request=req, intensity=req.intensity)
            self._runs[run_id] = rec
            return rec

    async def get_run(self, run_id: str) -> RunRecord | None:
        async with self._lock:
            return self._runs.get(run_id)

    async def save_run(self, rec: RunRecord) -> None:
        async with self._lock:
            self._runs[rec.id] = rec

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
