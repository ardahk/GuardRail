#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from backend.security.service import evaluate_prompt_security


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "fixtures" / "golden_verdicts.json"


def main() -> int:
    if not DATASET.exists():
        print(f"Dataset not found: {DATASET}")
        return 1

    rows = json.loads(DATASET.read_text(encoding="utf-8"))
    total = len(rows)
    matched = 0
    tp = fp = fn = 0
    details: list[dict] = []

    for row in rows:
        expected = set(row.get("expected_results", []))
        response_text = str(row.get("chatbot_response", ""))
        category = str(row.get("category", ""))
        try:
            evaluation = evaluate_prompt_security(
                system_prompt=str(row.get("system_prompt", "")),
                user_prompt=str(row.get("user_prompt", "")),
                context={"category": category, "chatbot_response": response_text},
            )
        except Exception as exc:
            print(f"Judge call failed for {row.get('id')}: {exc}")
            return 2

        predicted = str(evaluation.normalized_result)
        if predicted in expected:
            matched += 1

        expected_positive = any(x in {"partial_fail", "critical_fail"} for x in expected)
        predicted_positive = predicted in {"partial_fail", "critical_fail"}
        if predicted_positive and expected_positive:
            tp += 1
        elif predicted_positive and not expected_positive:
            fp += 1
        elif (not predicted_positive) and expected_positive:
            fn += 1

        details.append(
            {
                "id": row.get("id"),
                "category": category,
                "predicted": predicted,
                "expected": sorted(expected),
                "severity": evaluation.normalized_severity,
                "confidence": evaluation.judge_confidence,
                "flags": evaluation.judge_flags,
            }
        )

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    report = {
        "dataset": str(DATASET),
        "total": total,
        "matched": matched,
        "accuracy": round(matched / total, 3) if total else 0.0,
        "precision_fail_detection": round(precision, 3),
        "recall_fail_detection": round(recall, 3),
        "details": details,
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

