"""Verify that real OpenAI error text is preserved through the judge → service
→ orchestrator chain rather than being silently swallowed.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from backend.security.config import SecurityModelConfig
from backend.security.openai_judge_client import JudgeError, OpenAIJudgeClient


def _config() -> SecurityModelConfig:
    return SecurityModelConfig(api_key="sk-test", model="gpt-5-mini-2025-08-07")


def _fake_http_error(status: int, body: str) -> HTTPError:
    return HTTPError(
        url="https://api.openai.com/v1/chat/completions",
        code=status,
        msg=f"status {status}",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body.encode("utf-8")),
    )


class _NoopSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def test_judge_401_includes_real_body_excerpt(monkeypatch):
    sleep = _NoopSleep()
    monkeypatch.setattr("backend.security.openai_judge_client.time.sleep", sleep)
    monkeypatch.setattr(
        "backend.security.openai_judge_client.urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(
            _fake_http_error(401, '{"error":{"message":"Invalid API key"}}')
        ),
    )

    client = OpenAIJudgeClient(_config())
    with pytest.raises(JudgeError) as exc_info:
        client.judge(system_prompt="", user_prompt="x", context={}, conversation_history=[])

    message = str(exc_info.value)
    assert "401" in message
    assert "Invalid API key" in message
    # 4xx must NOT trigger a retry sleep
    assert sleep.calls == []


def test_judge_retries_once_on_500_then_succeeds(monkeypatch):
    sleep = _NoopSleep()
    monkeypatch.setattr("backend.security.openai_judge_client.time.sleep", sleep)

    success_body = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "result": "pass",
                            "severity": 1,
                            "rationale_summary": "Refused safely.",
                            "evidence_spans": [],
                        }
                    )
                }
            }
        ]
    }

    class _Resp:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *_a) -> None:
            return None

        def read(self) -> bytes:
            return self._body

    calls = {"n": 0}

    def fake_urlopen(*_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _fake_http_error(500, "transient upstream error")
        return _Resp(json.dumps(success_body).encode("utf-8"))

    monkeypatch.setattr("backend.security.openai_judge_client.urlopen", fake_urlopen)

    client = OpenAIJudgeClient(_config())
    out = client.judge(system_prompt="", user_prompt="x", context={}, conversation_history=[])
    assert out.result.value == "pass"
    # The retry should have slept exactly once.
    assert len(sleep.calls) == 1


def test_judge_two_500s_raise_with_body_excerpt(monkeypatch):
    sleep = _NoopSleep()
    monkeypatch.setattr("backend.security.openai_judge_client.time.sleep", sleep)

    def fake_urlopen(*_a, **_k):
        raise _fake_http_error(500, "rate limit upstream meltdown")

    monkeypatch.setattr("backend.security.openai_judge_client.urlopen", fake_urlopen)

    client = OpenAIJudgeClient(_config())
    with pytest.raises(JudgeError) as exc_info:
        client.judge(system_prompt="", user_prompt="x", context={}, conversation_history=[])

    msg = str(exc_info.value)
    assert "500" in msg
    assert "rate limit upstream meltdown" in msg
    # Should have slept exactly once between the two attempts.
    assert len(sleep.calls) == 1


def test_judge_urlerror_message_propagates(monkeypatch):
    sleep = _NoopSleep()
    monkeypatch.setattr("backend.security.openai_judge_client.time.sleep", sleep)

    def fake_urlopen(*_a, **_k):
        raise URLError("connection refused")

    monkeypatch.setattr("backend.security.openai_judge_client.urlopen", fake_urlopen)

    client = OpenAIJudgeClient(_config())
    with pytest.raises(JudgeError) as exc_info:
        client.judge(system_prompt="", user_prompt="x", context={}, conversation_history=[])

    assert "connection refused" in str(exc_info.value)


def test_judge_schema_mismatch_includes_payload_excerpt(monkeypatch):
    monkeypatch.setattr("backend.security.openai_judge_client.time.sleep", lambda *_a: None)

    bad_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({"result": "pass"})  # missing severity, rationale
                }
            }
        ]
    }

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return None

        def read(self):
            return json.dumps(bad_payload).encode("utf-8")

    monkeypatch.setattr(
        "backend.security.openai_judge_client.urlopen",
        lambda *_a, **_k: _Resp(),
    )

    client = OpenAIJudgeClient(_config())
    with pytest.raises(JudgeError) as exc_info:
        client.judge(system_prompt="", user_prompt="x", context={}, conversation_history=[])

    assert "schema validation" in str(exc_info.value)


def test_legacy_aliases_still_exist():
    """The Gemini-* shim must remain to avoid breaking external imports."""
    from backend.security.gemini_client import GeminiJudgeClient, GeminiJudgeError

    assert GeminiJudgeError is JudgeError
    assert GeminiJudgeClient is OpenAIJudgeClient
