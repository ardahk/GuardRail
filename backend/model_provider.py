from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_PROVIDER = "xai"
PROVIDER_DEFAULTS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "model": "gpt-5-mini-2025-08-07",
    },
    "xai": {
        "base_url": "https://api.x.ai/v1",
        "api_key_env": "XAI_API_KEY",
        "model": "grok-4.3",
    },
}


class ModelProviderConfigError(RuntimeError):
    """Raised when an attacker or judge provider is incomplete."""


@dataclass(frozen=True)
class ProviderModelConfig:
    provider: str
    api_key: str
    base_url: str
    model: str

    @property
    def chat_completions_url(self) -> str:
        return f"{self.base_url}/chat/completions"


def resolve_model_config(stage: str) -> ProviderModelConfig:
    """Resolve a provider/model for ``judge`` or ``attacker``.

    MODEL_PROVIDER and MODEL_NAME are the convenient shared preset. The
    stage-specific variables remain available when the two roles need to use
    different providers or models.
    """

    normalized_stage = stage.strip().lower()
    if normalized_stage not in {"judge", "attacker"}:
        raise ValueError(f"Unsupported model stage: {stage}")

    provider_env = "JUDGE_PROVIDER" if normalized_stage == "judge" else "ATTACKER_PROVIDER"
    model_env = "SECURITY_JUDGE_MODEL" if normalized_stage == "judge" else "ATTACKER_MODEL"
    provider = (
        os.getenv(provider_env, "").strip().lower()
        or os.getenv("MODEL_PROVIDER", DEFAULT_PROVIDER).strip().lower()
    )
    defaults = PROVIDER_DEFAULTS.get(provider)
    if defaults is None:
        supported = ", ".join(sorted(PROVIDER_DEFAULTS))
        raise ModelProviderConfigError(
            f"Unsupported {normalized_stage} provider '{provider}'. Supported providers: {supported}."
        )

    provider_prefix = provider.upper()
    api_key_env = str(defaults["api_key_env"])
    api_key = os.getenv(api_key_env, "").strip()
    if not api_key:
        raise ModelProviderConfigError(
            f"Missing {api_key_env} for {normalized_stage} provider '{provider}'."
        )

    model = (
        os.getenv(model_env, "").strip()
        or os.getenv("MODEL_NAME", "").strip()
        or str(defaults["model"])
    )
    base_url = (
        os.getenv(f"{provider_prefix}_BASE_URL", "").strip()
        or str(defaults["base_url"])
    ).rstrip("/")
    if not base_url:
        raise ModelProviderConfigError(f"Missing base URL for provider '{provider}'.")

    return ProviderModelConfig(
        provider=provider,
        api_key=api_key,
        base_url=base_url,
        model=model,
    )
