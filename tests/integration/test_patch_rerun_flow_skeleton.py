"""Integration skeleton for patch + rerun flow.

Expected flow:
1. Submit medium-risk payload.
2. Receive patch recommendation.
3. Submit patched payload for rerun.
4. Verify final decision transitions to allow.

Enable this suite by setting ENABLE_INTEGRATION_TESTS=true in .env.
"""

import os

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("ENABLE_INTEGRATION_TESTS", "false").lower() != "true",
    reason="Set ENABLE_INTEGRATION_TESTS=true to run integration skeletons.",
)


def test_patch_and_rerun_flow_contract(expected_responses_fixture):
    medium = expected_responses_fixture["medium"]
    patched = expected_responses_fixture["patched_rerun"]

    # TODO(worker owning backend/api contract): replace these fixture assertions
    # with real API calls once route + schema are finalized.
    assert medium["action"] == "patch"
    assert patched["action"] == "allow"
    assert patched["status"] == "clean"
