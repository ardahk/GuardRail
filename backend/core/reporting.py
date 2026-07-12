from __future__ import annotations

from collections import defaultdict

from .models import CategorySummary, CoverageResult, LaneResult, RunReport
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

    attempted = sorted(category_buckets)
    requested = sorted(set(run.request.attack_categories or attempted))
    skipped = sorted(set(requested) - set(attempted))
    input_channels = sorted({lane.input_channel or "chat" for lane in lanes if not lane.error})
    capture_failures = sum(
        1 for lane in lanes if lane.error and run.request.target.target_type == "browser"
    )
    judge_degraded = sum(
        1 for lane in lanes if lane.judge_status in {"unjudged", "heuristic_judged", "error"}
    )
    coverage = CoverageResult(
        profile=run.request.coverage_profile,
        attempted_categories=attempted,
        skipped_categories=skipped,
        supported_input_channels=input_channels,
        untested_input_channels=sorted(
            {"retrieved_web_content", "document_or_page_content", "chat_with_tools"}
            - set(input_channels)
        ),
        browser_capture_failures=capture_failures,
        judge_degraded=judge_degraded,
        complete=not skipped and capture_failures == 0 and judge_degraded == 0,
    )

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
        coverage=coverage.model_dump(mode="json"),
    )


def to_sarif(report: dict) -> dict:
    results = []
    for finding in report.get("findings", []):
        if finding.get("state") in {"rejected", "not_tested"}:
            continue
        mappings = finding.get("standards_mapping") or [finding.get("category", "guardrail")]
        results.append(
            {
                "ruleId": mappings[0],
                "level": "error" if int(finding.get("severity", 0)) >= 7 else "warning",
                "message": {"text": finding.get("title", "GuardRail security finding")},
                "properties": {
                    "findingId": finding.get("id"),
                    "state": finding.get("state"),
                    "confidence": finding.get("confidence"),
                    "standards": mappings,
                    "remediation": finding.get("remediation", []),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "GuardRail", "version": "0.2.0"}},
                "results": results,
            }
        ],
    }
