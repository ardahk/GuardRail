from __future__ import annotations

from dataclasses import dataclass

from backend.model_provider import ModelProviderConfigError, resolve_model_config


DEFAULT_JUDGE_MODEL = "grok-4.3"
XAI_BASE_URL = "https://api.x.ai/v1"


class ModelUnavailableError(RuntimeError):
    """Raised when configured model cannot be used."""


class SecurityConfigError(RuntimeError):
    """Raised when security configuration is invalid."""


@dataclass(frozen=True)
class SecurityModelConfig:
    api_key: str
    model: str
    base_url: str = XAI_BASE_URL
    provider: str = "xai"
    temperature: float = 0.0
    timeout_seconds: float = 45.0

    @classmethod
    def from_env(cls) -> "SecurityModelConfig":
        try:
            resolved = resolve_model_config("judge")
        except ModelProviderConfigError as exc:
            raise SecurityConfigError(str(exc)) from exc
        return cls(
            api_key=resolved.api_key,
            model=resolved.model,
            base_url=resolved.base_url,
            provider=resolved.provider,
        )


def load_validated_security_config() -> SecurityModelConfig:
    config = SecurityModelConfig.from_env()
    from .openai_judge_client import OpenAIJudgeClient

    OpenAIJudgeClient(config).assert_model_available()
    return config
