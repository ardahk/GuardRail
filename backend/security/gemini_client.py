"""Backward-compatibility shim.

This module used to host the (misleadingly-named) ``GeminiJudgeClient`` /
``GeminiJudgeError`` symbols even though the implementation always called
OpenAI. The real implementation now lives in :mod:`openai_judge_client`.
The aliases below keep any pre-existing imports working.
"""
from __future__ import annotations

from .openai_judge_client import JudgeError as JudgeError
from .openai_judge_client import OpenAIJudgeClient as OpenAIJudgeClient

# Legacy names — kept so older imports do not break.
GeminiJudgeError = JudgeError
GeminiJudgeClient = OpenAIJudgeClient

__all__ = [
    "GeminiJudgeClient",
    "GeminiJudgeError",
    "JudgeError",
    "OpenAIJudgeClient",
]
