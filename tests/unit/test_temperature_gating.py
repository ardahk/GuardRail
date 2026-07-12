"""Verify that `model_rejects_temperature` correctly classifies model families
so we don't 400 on GPT-5 / o-series by sending an unsupported `temperature`
parameter, while preserving temperature for the older `gpt-5.4-*` family
that accepts it.
"""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.security.openai_judge_client import model_rejects_temperature


def test_o_series_models_reject_temperature():
    assert model_rejects_temperature("o1")
    assert model_rejects_temperature("o3-mini")
    assert model_rejects_temperature("o4-preview")


def test_gpt5_dash_family_rejects_temperature():
    # The user's observed failing model:
    assert model_rejects_temperature("gpt-5-mini-2025-08-07")
    assert model_rejects_temperature("gpt-5-mini")
    assert model_rejects_temperature("gpt-5.5")
    assert model_rejects_temperature("gpt-5.6-mini")


def test_gpt5_4_family_still_accepts_temperature():
    # gpt-5.4-mini is the older, dot-separated family that DID accept temperature.
    assert not model_rejects_temperature("gpt-5.4")
    assert not model_rejects_temperature("gpt-5.4-mini")
    assert not model_rejects_temperature("gpt-5.4-nano")


def test_classic_gpt_models_accept_temperature():
    assert not model_rejects_temperature("gpt-4o-mini")
    assert not model_rejects_temperature("gpt-4.1")
    assert not model_rejects_temperature("gpt-3.5-turbo")
