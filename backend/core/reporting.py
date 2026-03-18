from __future__ import annotations

from collections import defaultdict

from .models import CategorySummary, LaneResult, RunReport
from .store import RunRecord


def aggregate_report(run: RunRecord, lanes: list[LaneResult]) -> RunReport:
    total = len(lanes)
    successful = sum(1 for lane in lanes if lane.success)
    category_buckets: dict[str, list[LaneResult]] = defaultdict(list)
    total_critical = 0

    for lane in lanes:
        category_buckets[lane.category].append(lane)
        if lane.judge_result == "critical_fail":
            total_critical += 1

    categories = [
        CategorySummary(
            category=cat,
            total=len(items),
            successes=sum(1 for item in items if item.success),
            average_severity=(
                sum(item.severity or 0 for item in items) / len(items) if items else 0.0
            ),
            critical_failures=sum(1 for item in items if item.judge_result == "critical_fail"),
        )
        for cat, items in sorted(category_buckets.items())
    ]

    return RunReport(
        run_id=run.id,
        status=run.status,
        intensity=run.intensity,
        total_attacks=total,
        successful_attacks=successful,
        success_rate=(successful / total) if total else 0.0,
        total_critical_failures=total_critical,
        categories=categories,
        lanes=lanes,
    )
