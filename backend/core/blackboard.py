from __future__ import annotations

import asyncio
from collections import defaultdict
from uuid import uuid4

from .models import ExploitHypothesis, FindingEvidence
from .persistence import DurableRepository


class RunBlackboard:
    """Run-scoped, bounded hypothesis exchange between attack lanes."""

    def __init__(self, repository: DurableRepository | None = None):
        self._repository = repository
        self._items: dict[str, list[ExploitHypothesis]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def publish(
        self,
        *,
        run_id: str,
        project_id: str,
        source_lane_id: str,
        attack_family: str,
        mechanism: str,
        preconditions: list[str],
        evidence: list[FindingEvidence],
        confidence: float,
        target_fingerprint: str,
        safe_mutation_recipe: str,
        expected_validation_signal: str,
        quarantined: bool,
    ) -> ExploitHypothesis:
        hypothesis = ExploitHypothesis(
            id=str(uuid4()),
            run_id=run_id,
            project_id=project_id,
            source_lane_id=source_lane_id,
            attack_family=attack_family,
            mechanism=mechanism or "unknown",
            preconditions=preconditions,
            evidence=evidence[:12],
            confidence=max(0.0, min(1.0, confidence)),
            target_fingerprint=target_fingerprint,
            safe_mutation_recipe=safe_mutation_recipe[:500],
            expected_validation_signal=expected_validation_signal[:500],
            quarantined=quarantined,
        )
        async with self._lock:
            self._items[run_id].append(hypothesis)
        if self._repository is not None:
            await asyncio.to_thread(self._repository.save_hypothesis, hypothesis)
        return hypothesis

    async def compatible(
        self,
        *,
        run_id: str,
        lane_id: str,
        attack_family: str,
        mechanism: str,
        fanout_limit: int,
    ) -> list[ExploitHypothesis]:
        if fanout_limit <= 0:
            return []
        async with self._lock:
            output: list[ExploitHypothesis] = []
            for item in reversed(self._items.get(run_id, [])):
                if item.source_lane_id == lane_id or item.quarantined:
                    continue
                compatible = (
                    item.attack_family == attack_family
                    or item.mechanism == mechanism
                    or item.affected_capability == "chat"
                )
                if not compatible or item.fanout_count >= fanout_limit:
                    continue
                updated = item.model_copy(update={"fanout_count": item.fanout_count + 1})
                index = self._items[run_id].index(item)
                self._items[run_id][index] = updated
                output.append(updated)
                if len(output) >= fanout_limit:
                    break
        for item in output:
            if self._repository is not None:
                await asyncio.to_thread(self._repository.save_hypothesis, item)
        return output

    async def record_reproduction(self, run_id: str, hypothesis_id: str) -> ExploitHypothesis | None:
        async with self._lock:
            for index, item in enumerate(self._items.get(run_id, [])):
                if item.id != hypothesis_id:
                    continue
                updated = item.model_copy(update={"reproduction_count": item.reproduction_count + 1})
                self._items[run_id][index] = updated
                break
            else:
                return None
        if self._repository is not None:
            await asyncio.to_thread(self._repository.save_hypothesis, updated)
        return updated

    async def list(self, run_id: str) -> list[ExploitHypothesis]:
        async with self._lock:
            return list(self._items.get(run_id, []))

