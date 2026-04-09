from __future__ import annotations

from typing import Any

import httpx

from .models import TargetConfig


class OpenAICompatibleTargetAdapter:
    def __init__(self, cfg: TargetConfig):
        self.cfg = cfg

    async def chat(
        self,
        messages: list[dict[str, str]],
        session_id: str | None = None,
    ) -> dict[str, Any]:
        url = f"{self.cfg.base_url.rstrip('/')}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.cfg.api_key}",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {"model": self.cfg.model, "messages": messages}

        if self.cfg.target_type == "browser" and session_id:
            body["session_id"] = session_id
            body["target_url"] = self.cfg.playwright_target_url
            body["selectors"] = self.cfg.playwright_selectors or {}

        # Browser mode needs longer timeout: page load + widget init + bot thinking + streaming
        timeout = 120 if self.cfg.target_type == "browser" else 60
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, headers=headers, json=body)
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                proxy_message = ""
                try:
                    payload = resp.json()
                    proxy_message = str(payload.get("error", {}).get("message", "")).strip()
                except Exception:
                    proxy_message = resp.text.strip()
                if proxy_message:
                    raise RuntimeError(proxy_message) from exc
                raise
            return resp.json()

    async def close_session(self, session_id: str) -> None:
        if self.cfg.target_type != "browser":
            return
        url = f"{self.cfg.base_url.rstrip('/')}/sessions/{session_id}"
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                await client.delete(url)
            except httpx.HTTPError:
                pass

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
