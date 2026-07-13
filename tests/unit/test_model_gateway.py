from __future__ import annotations

import asyncio
import time

import pytest

from backend.core.model_gateway import AsyncModelGateway, ModelGatewayError


def test_model_gateway_returns_validated_function_result():
    gateway = AsyncModelGateway(concurrency=1, timeout_seconds=1)
    result = asyncio.run(gateway.call("judge", lambda value: {"result": value}, "pass"))
    assert result == {"result": "pass"}


def test_model_gateway_surfaces_typed_timeout():
    gateway = AsyncModelGateway(concurrency=1, timeout_seconds=0.01)

    with pytest.raises(ModelGatewayError, match="judge model gateway failed: timed out"):
        asyncio.run(gateway.call("judge", lambda: time.sleep(0.05)))
