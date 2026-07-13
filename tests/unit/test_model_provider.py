from __future__ import annotations

import pytest

from backend.model_provider import ModelProviderConfigError, resolve_model_config


def _clear_model_env(monkeypatch) -> None:
    for name in (
        "MODEL_PROVIDER",
        "MODEL_NAME",
        "JUDGE_PROVIDER",
        "ATTACKER_PROVIDER",
        "SECURITY_JUDGE_MODEL",
        "ATTACKER_MODEL",
        "XAI_BASE_URL",
        "OPENAI_BASE_URL",
        "XAI_API_KEY",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def test_shared_xai_preset_configures_both_roles(monkeypatch):
    _clear_model_env(monkeypatch)
    monkeypatch.setenv("MODEL_PROVIDER", "xai")
    monkeypatch.setenv("MODEL_NAME", "grok-4.3")
    monkeypatch.setenv("XAI_API_KEY", "xai-test")

    judge = resolve_model_config("judge")
    attacker = resolve_model_config("attacker")

    assert judge == attacker
    assert judge.provider == "xai"
    assert judge.model == "grok-4.3"
    assert judge.base_url == "https://api.x.ai/v1"
    assert judge.chat_completions_url == "https://api.x.ai/v1/chat/completions"


def test_switching_shared_preset_to_openai(monkeypatch):
    _clear_model_env(monkeypatch)
    monkeypatch.setenv("MODEL_PROVIDER", "openai")
    monkeypatch.setenv("MODEL_NAME", "gpt-5-mini-2025-08-07")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    config = resolve_model_config("judge")

    assert config.provider == "openai"
    assert config.model == "gpt-5-mini-2025-08-07"
    assert config.base_url == "https://api.openai.com/v1"


def test_stage_override_can_mix_providers(monkeypatch):
    _clear_model_env(monkeypatch)
    monkeypatch.setenv("MODEL_PROVIDER", "xai")
    monkeypatch.setenv("MODEL_NAME", "grok-4.3")
    monkeypatch.setenv("XAI_API_KEY", "xai-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("JUDGE_PROVIDER", "openai")
    monkeypatch.setenv("SECURITY_JUDGE_MODEL", "gpt-5-mini")

    judge = resolve_model_config("judge")
    attacker = resolve_model_config("attacker")

    assert (judge.provider, judge.model) == ("openai", "gpt-5-mini")
    assert (attacker.provider, attacker.model) == ("xai", "grok-4.3")


def test_selected_provider_requires_its_own_key(monkeypatch):
    _clear_model_env(monkeypatch)
    monkeypatch.setenv("MODEL_PROVIDER", "xai")
    monkeypatch.setenv("OPENAI_API_KEY", "wrong-provider-key")

    with pytest.raises(ModelProviderConfigError, match="Missing XAI_API_KEY"):
        resolve_model_config("judge")
