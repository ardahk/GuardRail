#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.security.calibration import evaluate_golden_set, load_golden_set
from backend.security.service import heuristic_keyword_judge


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate GuardRail's deterministic fallback judge")
    parser.add_argument("--golden", default=str(ROOT / "tests/fixtures/judge_golden_v1.json"))
    parser.add_argument("--output")
    args = parser.parse_args()
    report = evaluate_golden_set(load_golden_set(args.golden), heuristic_keyword_judge)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
