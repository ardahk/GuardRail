"""Unit-test skeleton for low/medium/high attack handling.

These tests intentionally validate fixture shape and expected policy decisions.
Wire them to the real classifier once the backend contract is finalized.
"""


def test_low_fixture_maps_to_allow(low_attack_fixture, expected_responses_fixture):
    assert low_attack_fixture["severity"] == "low"
    assert expected_responses_fixture["low"]["action"] == "allow"


def test_medium_fixture_maps_to_patch(medium_attack_fixture, expected_responses_fixture):
    assert medium_attack_fixture["severity"] == "medium"
    assert expected_responses_fixture["medium"]["action"] == "patch"


def test_high_fixture_maps_to_block(high_attack_fixture, expected_responses_fixture):
    assert high_attack_fixture["severity"] == "high"
    assert expected_responses_fixture["high"]["action"] == "block"
