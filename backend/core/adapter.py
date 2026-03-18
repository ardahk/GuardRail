from __future__ import annotations

from typing import Any

import httpx

from .models import TargetConfig


class OpenAICompatibleTargetAdapter:
    def __init__(self, cfg: TargetConfig):
        self.cfg = cfg

    async def chat(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        url = f"{self.cfg.base_url.rstrip('/')}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.cfg.api_key}",
            "Content-Type": "application/json",
        }
        body = {"model": self.cfg.model, "messages": messages}

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def extract_text(response_json: dict[str, Any]) -> str:
        choices = response_json.get("choices", [])
        if not choices:
            return ""
        msg = choices[0].get("message", {})
        content = msg.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = [c.get("text", "") for c in content if isinstance(c, dict)]
            return "".join(parts)
        return ""
