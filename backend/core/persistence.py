from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import ExploitHypothesis, Finding, FindingReview, FindingState, ReviewDecision


SCHEMA_VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DurableRepository:
    """Small SQLite repository for self-hosted projects and durable evidence.

    The orchestration hot path remains in memory; snapshots are persisted after
    each state transition. Evidence is bounded and redacted before this layer.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.RLock()
        if db_path != ":memory:":
            Path(db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS projects(
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    retention_days INTEGER NOT NULL DEFAULT 30,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_snapshots(
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS hypotheses(
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings(
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reviews(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_project_run ON findings(project_id, run_id);
                CREATE INDEX IF NOT EXISTS idx_hypotheses_project_run ON hypotheses(project_id, run_id);
                """
            )
            count = conn.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0]
            if count == 0:
                conn.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
            conn.execute(
                "INSERT OR IGNORE INTO projects(id, name, retention_days, created_at) VALUES ('local', 'Local project', 30, ?)",
                (_now(),),
            )
            conn.commit()

    def create_project(self, project_id: str, name: str, retention_days: int = 30) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO projects(id, name, retention_days, created_at) VALUES (?, ?, ?, ?)",
                (project_id, name, max(1, min(3650, retention_days)), _now()),
            )
            conn.commit()
        return self.get_project(project_id) or {}

    def list_projects(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM projects ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return dict(row) if row else None

    def update_project(
        self,
        project_id: str,
        *,
        name: str | None = None,
        retention_days: int | None = None,
    ) -> dict[str, Any] | None:
        current = self.get_project(project_id)
        if current is None:
            return None
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE projects SET name = ?, retention_days = ? WHERE id = ?",
                (
                    name or current["name"],
                    retention_days if retention_days is not None else current["retention_days"],
                    project_id,
                ),
            )
            conn.commit()
        return self.get_project(project_id)

    def enforce_retention(
        self,
        project_id: str | None = None,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        reference = now or datetime.now(timezone.utc)
        totals = {"runs": 0, "hypotheses": 0, "findings": 0, "reviews": 0}
        expired_run_ids: list[str] = []
        with self._lock, self._connect() as conn:
            sql = "SELECT id, retention_days FROM projects"
            args: tuple[Any, ...] = ()
            if project_id is not None:
                sql += " WHERE id = ?"
                args = (project_id,)
            projects = conn.execute(sql, args).fetchall()
            for project in projects:
                cutoff = (reference - timedelta(days=int(project["retention_days"]))).isoformat()
                expired = conn.execute(
                    "SELECT id FROM run_snapshots WHERE project_id = ? AND updated_at < ?",
                    (project["id"], cutoff),
                ).fetchall()
                run_ids = [row["id"] for row in expired]
                expired_run_ids.extend(run_ids)
                for run_id in run_ids:
                    review_cur = conn.execute(
                        "DELETE FROM reviews WHERE finding_id IN (SELECT id FROM findings WHERE run_id = ?)",
                        (run_id,),
                    )
                    totals["reviews"] += int(review_cur.rowcount)
                    for table, key in (("hypotheses", "hypotheses"), ("findings", "findings")):
                        cur = conn.execute(f"DELETE FROM {table} WHERE run_id = ?", (run_id,))
                        totals[key] += int(cur.rowcount)
                    cur = conn.execute("DELETE FROM run_snapshots WHERE id = ?", (run_id,))
                    totals["runs"] += int(cur.rowcount)
            conn.commit()
        return {**totals, "expired_run_ids": expired_run_ids}

    def delete_project(self, project_id: str) -> bool:
        if project_id == "local":
            return False
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM reviews WHERE finding_id IN (SELECT id FROM findings WHERE project_id = ?)",
                (project_id,),
            )
            for table in ("run_snapshots", "hypotheses", "findings"):
                conn.execute(f"DELETE FROM {table} WHERE project_id = ?", (project_id,))
            cur = conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            conn.commit()
            return cur.rowcount > 0

    def clear_project_data(self, project_id: str) -> dict[str, int]:
        deleted: dict[str, int] = {}
        with self._lock, self._connect() as conn:
            review_cur = conn.execute(
                "DELETE FROM reviews WHERE finding_id IN (SELECT id FROM findings WHERE project_id = ?)",
                (project_id,),
            )
            deleted["reviews"] = int(review_cur.rowcount)
            for table in ("run_snapshots", "hypotheses", "findings"):
                cur = conn.execute(f"DELETE FROM {table} WHERE project_id = ?", (project_id,))
                deleted[table] = int(cur.rowcount)
            conn.commit()
        return deleted

    def save_run_snapshot(self, run_id: str, project_id: str, status: str, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO run_snapshots(id, project_id, status, payload, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET status=excluded.status, payload=excluded.payload,
                updated_at=excluded.updated_at""",
                (run_id, project_id, status, encoded, _now()),
            )
            conn.commit()

    def load_run_snapshots(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT payload FROM run_snapshots ORDER BY updated_at").fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            try:
                output.append(json.loads(row[0]))
            except json.JSONDecodeError:
                continue
        return output

    def save_hypothesis(self, hypothesis: ExploitHypothesis) -> None:
        payload = json.dumps(hypothesis.model_dump(mode="json"), ensure_ascii=True)
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO hypotheses(id, project_id, run_id, payload, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at""",
                (hypothesis.id, hypothesis.project_id, hypothesis.run_id, payload, _now()),
            )
            conn.commit()

    def list_hypotheses(self, project_id: str, run_id: str | None = None) -> list[ExploitHypothesis]:
        sql = "SELECT payload FROM hypotheses WHERE project_id = ?"
        args: list[Any] = [project_id]
        if run_id:
            sql += " AND run_id = ?"
            args.append(run_id)
        sql += " ORDER BY updated_at"
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [ExploitHypothesis.model_validate_json(row[0]) for row in rows]

    def save_finding(self, finding: Finding) -> None:
        payload = json.dumps(finding.model_dump(mode="json"), ensure_ascii=True)
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO findings(id, project_id, run_id, state, payload, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET state=excluded.state, payload=excluded.payload,
                updated_at=excluded.updated_at""",
                (finding.id, finding.project_id, finding.run_id, finding.state.value, payload, _now()),
            )
            conn.commit()

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT payload FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return Finding.model_validate_json(row[0]) if row else None

    def list_finding_reviews(self, finding_id: str) -> list[FindingReview]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT id, finding_id, state, rationale, reviewer, created_at "
                "FROM reviews WHERE finding_id = ? ORDER BY id",
                (finding_id,),
            ).fetchall()
        return [FindingReview.model_validate(dict(row)) for row in rows]

    def list_findings(self, project_id: str, run_id: str | None = None) -> list[Finding]:
        sql = "SELECT payload FROM findings WHERE project_id = ?"
        args: list[Any] = [project_id]
        if run_id:
            sql += " AND run_id = ?"
            args.append(run_id)
        sql += " ORDER BY updated_at DESC"
        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [Finding.model_validate_json(row[0]) for row in rows]

    def review_finding(self, finding_id: str, decision: ReviewDecision) -> Finding | None:
        finding = self.get_finding(finding_id)
        if finding is None:
            return None
        allowed = {
            FindingState.CONFIRMED,
            FindingState.REJECTED,
            FindingState.NEEDS_RETEST,
            FindingState.PENDING,
        }
        if decision.state not in allowed:
            raise ValueError("Review state must be pending, confirmed, rejected, or needs_retest")
        confirmation_status = {
            FindingState.CONFIRMED: "human_confirmed",
            FindingState.REJECTED: "human_rejected",
            FindingState.NEEDS_RETEST: "needs_retest",
            FindingState.PENDING: finding.confirmation_status,
        }[decision.state]
        updated = finding.model_copy(
            update={"state": decision.state, "confirmation_status": confirmation_status}
        )
        self.save_finding(updated)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO reviews(finding_id, state, rationale, reviewer, created_at) VALUES (?, ?, ?, ?, ?)",
                (finding_id, decision.state.value, decision.rationale, decision.reviewer, _now()),
            )
            conn.commit()
        return updated
