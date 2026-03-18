from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .models import AttackDefinition


class AttackLibraryLoader:
    def __init__(self, attack_dir: Path):
        self.attack_dir = attack_dir

    def load(self) -> list[AttackDefinition]:
        attacks: list[AttackDefinition] = []
        for path in sorted(self.attack_dir.glob("*")):
            if not path.is_file() or path.suffix.lower() not in {".json", ".yaml", ".yml"}:
                continue
            loaded = self._load_file(path)
            attacks.extend(loaded)
        return attacks

    def _load_file(self, path: Path) -> list[AttackDefinition]:
        raw: Any
        if path.suffix.lower() == ".json":
            raw = json.loads(path.read_text())
        else:
            raw = yaml.safe_load(path.read_text())

        rows = raw if isinstance(raw, list) else [raw]
        parsed: list[AttackDefinition] = []

        for row in rows:
            normalized = self._normalize(row)
            try:
                parsed.append(AttackDefinition.model_validate(normalized))
            except ValidationError as exc:
                raise ValueError(f"Invalid attack schema in {path.name}: {exc}") from exc

        return parsed

    @staticmethod
    def _normalize(row: dict[str, Any]) -> dict[str, Any]:
        criteria = row.get("success_criteria", [])
        if isinstance(criteria, str):
            row["success_criteria"] = [criteria]
        return row
