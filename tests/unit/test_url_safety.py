from __future__ import annotations

import asyncio

import pytest

from backend.core.url_safety import UnsafeTargetURLError, validate_outbound_url


def test_loopback_fixture_url_is_allowed():
    assert asyncio.run(validate_outbound_url("http://127.0.0.1:7080/inline")) == "http://127.0.0.1:7080/inline"


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://user:password@example.com",
    "http://169.254.169.254/latest/meta-data",
    "http://0.0.0.0/",
])
def test_unsafe_target_urls_are_blocked(url):
    with pytest.raises(UnsafeTargetURLError):
        asyncio.run(validate_outbound_url(url))


def test_private_targets_require_explicit_operator_opt_in(monkeypatch):
    monkeypatch.delenv("GUARDRAIL_ALLOW_PRIVATE_TARGETS", raising=False)
    with pytest.raises(UnsafeTargetURLError, match="private address"):
        asyncio.run(validate_outbound_url("http://10.20.30.40/chat"))

    monkeypatch.setenv("GUARDRAIL_ALLOW_PRIVATE_TARGETS", "true")
    assert asyncio.run(validate_outbound_url("http://10.20.30.40/chat")) == "http://10.20.30.40/chat"
