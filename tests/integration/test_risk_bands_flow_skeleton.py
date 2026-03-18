"""Integration skeleton for low/medium/high policy decisions.

Enable via ENABLE_INTEGRATION_TESTS=true.
Replace fixture-only checks with real API calls once endpoint contracts are stable.
"""

import os

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("ENABLE_INTEGRATION_TESTS", "false").lower() != "true",
    reason="Set ENABLE_INTEGRATION_TESTS=true to run integration skeletons.",
)


def test_low_medium_high_contract(expected_responses_fixture):
    assert expected_responses_fixture["low"]["action"] == "allow"
    assert expected_responses_fixture["medium"]["action"] == "patch"
    assert expected_responses_fixture["high"]["action"] == "block"
