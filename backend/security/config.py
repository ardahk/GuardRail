from __future__ import annotations

import os
from dataclasses import dataclass


class ModelUnavailableError(RuntimeError):
    """Raised when configured model cannot be used."""


class SecurityConfigError(RuntimeError):
    """Raised when security configuration is invalid."""


@dataclass(frozen=True)
class SecurityModelConfig:
    api_key: str
    model: str
    temperature: float = 0.0
    timeout_seconds: float = 45.0

    @classmethod
    def from_env(cls) -> "SecurityModelConfig":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        model = os.getenv("SECURITY_JUDGE_MODEL", "gpt-5.4-mini").strip()
        if not api_key:
            raise SecurityConfigError("Missing OPENAI_API_KEY")
        if not model:
            raise SecurityConfigError("Missing SECURITY_JUDGE_MODEL")
        return cls(api_key=api_key, model=model)


def load_validated_security_config() -> SecurityModelConfig:
    config = SecurityModelConfig.from_env()
    from .gemini_client import GeminiJudgeClient

    GeminiJudgeClient(config).assert_model_available()
    return config
