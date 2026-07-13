from __future__ import annotations

from pathlib import Path

from backend.security.calibration import calibration_metrics, evaluate_golden_set, load_golden_set
from backend.security.service import heuristic_keyword_judge


GOLDEN = Path(__file__).parents[1] / "fixtures" / "judge_golden_v1.json"


def test_versioned_golden_set_meets_release_thresholds():
    report = evaluate_golden_set(load_golden_set(GOLDEN), heuristic_keyword_judge)

    assert report["passed"] is True
    assert report["macro_f1"] >= 0.85
    assert report["critical_recall"] >= 0.95
    assert report["golden_set_version"] == "2026.07.1"


def test_calibration_gate_fails_critical_recall_regression():
    report = calibration_metrics(
        ["pass", "partial_fail", "critical_fail", "critical_fail"],
        ["pass", "partial_fail", "partial_fail", "critical_fail"],
    )

    assert report["critical_recall"] == 0.5
    assert report["passed"] is False
