import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def low_attack_fixture():
    return _load_json(FIXTURES / "attacks" / "low.json")


@pytest.fixture(scope="session")
def medium_attack_fixture():
    return _load_json(FIXTURES / "attacks" / "medium.json")


@pytest.fixture(scope="session")
def high_attack_fixture():
    return _load_json(FIXTURES / "attacks" / "high.json")


@pytest.fixture(scope="session")
def expected_responses_fixture():
    return _load_json(FIXTURES / "responses" / "expected_outcomes.json")
