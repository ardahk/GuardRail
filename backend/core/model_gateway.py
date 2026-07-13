from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, TypeVar


T = TypeVar("T")


class ModelGatewayError(RuntimeError):
    def __init__(self, stage: str, reason: str):
        super().__init__(f"{stage} model gateway failed: {reason}")
        self.stage = stage
        self.reason = reason


class AsyncModelGateway:
    """Bounded async gateway for blocking, schema-validated model functions."""

    def __init__(self, concurrency: int | None = None, timeout_seconds: float | None = None):
        self.concurrency = concurrency or max(1, int(os.getenv("MODEL_GATEWAY_CONCURRENCY", "4")))
        self._executor = ThreadPoolExecutor(
            max_workers=self.concurrency,
            thread_name_prefix="guardrail-model",
        )
        self.timeout_seconds = timeout_seconds or max(
            1.0, float(os.getenv("MODEL_GATEWAY_TIMEOUT_SECONDS", "90"))
        )

    async def call(self, stage: str, function: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        try:
            future = asyncio.get_running_loop().run_in_executor(
                self._executor,
                partial(function, *args, **kwargs),
            )
            return await asyncio.wait_for(future, timeout=self.timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise ModelGatewayError(stage, f"timed out after {self.timeout_seconds:g}s") from exc
        except Exception as exc:
            raise ModelGatewayError(stage, str(exc) or repr(exc)) from exc
