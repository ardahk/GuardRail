from __future__ import annotations

from collections import defaultdict

from .models import CategorySummary, CoverageResult, LaneResult, RunReport
from .store import RunRecord


def compare_runs(baseline: RunRecord, candidate: RunRecord) -> dict:
    baseline_attacks = sorted(item.id for item in baseline.attacks)
    candidate_attacks = sorted(item.id for item in candidate.attacks)
    baseline_judges = sorted({
        str(lane.provenance.get("judge_model", "unknown")) + ":" +
        str(lane.provenance.get("judge_prompt_version", "unknown"))
        for lane in baseline.lanes if lane.purpose == "coverage"
    })
    candidate_judges = sorted({
        str(lane.provenance.get("judge_model", "unknown")) + ":" +
        str(lane.provenance.get("judge_prompt_version", "unknown"))
        for lane in candidate.lanes if lane.purpose == "coverage"
    })
    reasons: list[str] = []
    if baseline.status.value != "completed":
        reasons.append("baseline_incomplete")
    if candidate.status.value != "completed":
        reasons.append("candidate_incomplete")
    if baseline.request.project_id != candidate.request.project_id:
        reasons.append("project_mismatch")
    if baseline_attacks != candidate_attacks:
        reasons.append("attack_corpus_mismatch")
    if baseline.request.coverage_profile != candidate.request.coverage_profile:
        reasons.append("coverage_profile_mismatch")
    if baseline.request.target.target_type != candidate.request.target.target_type:
        reasons.append("capture_method_mismatch")
    if baseline_judges != candidate_judges:
        reasons.append("judge_version_mismatch")
    if not baseline_judges or not candidate_judges or any("unknown" in value for value in baseline_judges + candidate_judges):
        reasons.append("judge_provenance_missing")

    def metrics(run: RunRecord) -> dict:
        report = run.report or {}
        return {
            "successful_attacks": int(report.get("successful_attacks", 0)),
            "success_rate": float(report.get("success_rate", 0.0)),
            "critical_failures": int(report.get("total_critical_failures", 0)),
            "coverage_complete": bool((report.get("coverage") or {}).get("complete", False)),
        }

    before = metrics(baseline)
    after = metrics(candidate)
    return {
        "schema_version": "1.0",
        "baseline_run_id": baseline.id,
        "candidate_run_id": candidate.id,
        "comparable": not reasons,
        "comparability_reasons": reasons,
        "corpus": {"attack_ids": baseline_attacks, "coverage_profile": baseline.request.coverage_profile},
        "judge_versions": {"baseline": baseline_judges, "candidate": candidate_judges},
        "capture_method": baseline.request.target.target_type,
        "baseline": before,
        "candidate": after,
        "delta": {
            "successful_attacks": after["successful_attacks"] - before["successful_attacks"],
            "success_rate": round(after["success_rate"] - before["success_rate"], 6),
            "critical_failures": after["critical_failures"] - before["critical_failures"],
        },
    }


def aggregate_report(run: RunRecord, lanes: list[LaneResult]) -> RunReport:
    coverage_lanes = [lane for lane in lanes if lane.purpose == "coverage"]
    confirmation_lanes = [lane for lane in lanes if lane.purpose == "confirmation"]
    total = len(coverage_lanes)
    successful = sum(1 for lane in coverage_lanes if lane.success)
    category_buckets: dict[str, list[LaneResult]] = defaultdict(list)
    total_critical = 0

    for lane in coverage_lanes:
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
    input_channels = sorted({lane.input_channel or "chat" for lane in coverage_lanes if not lane.error})
    capture_failures = sum(
        1 for lane in coverage_lanes if lane.error and run.request.target.target_type == "browser"
    )
    judge_degraded = sum(
        1 for lane in coverage_lanes if lane.judge_status in {"unjudged", "heuristic_judged", "capture_rejected", "error"}
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
        confirmation_lanes=len(confirmation_lanes),
        successful_confirmations=sum(1 for lane in confirmation_lanes if lane.success),
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
                    "reproductionCount": finding.get("reproduction_count", 0),
                    "confirmationStatus": finding.get("confirmation_status"),
                    "impactedCapability": finding.get("impacted_capability"),
                    "provenance": finding.get("provenance", {}),
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
