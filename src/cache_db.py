import sqlite3
from contextlib import closing
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

class AdvisoryCacheDB:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS processed_advisories (
                    article_id TEXT PRIMARY KEY,
                    title TEXT,
                    source TEXT,
                    matched_app TEXT,
                    severity TEXT,
                    first_seen_ts INTEGER
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pair_decisions (
                    article_id_low TEXT NOT NULL,
                    article_id_high TEXT NOT NULL,
                    same_event INTEGER NOT NULL CHECK (same_event IN (0, 1)),
                    decided_by TEXT NOT NULL CHECK (decided_by IN ('auto', 'human')),
                    decided_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT NOT NULL DEFAULT '',
                    confidence REAL,
                    PRIMARY KEY (article_id_low, article_id_high)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sent_ledger (
                    advisory_id TEXT NOT NULL,
                    recipient_team TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    PRIMARY KEY (advisory_id, recipient_team, content_hash)
                )
            """)
            conn.commit()

    def is_seen(self, article_id: str) -> bool:
        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM processed_advisories WHERE article_id = ?", (article_id,))
            return cursor.fetchone() is not None

    def mark_seen(self, article_id: str, title: str, source: str, matched_app: str, severity: str, timestamp: int):
        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO processed_advisories 
                (article_id, title, source, matched_app, severity, first_seen_ts)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (article_id, title, source, matched_app, severity, timestamp))
            conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM processed_advisories")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT severity, COUNT(*) FROM processed_advisories GROUP BY severity")
            breakdown = dict(cursor.fetchall())
            return {"total_tracked": total, "by_severity": breakdown}

    @staticmethod
    def _pair_ids(left_id: str, right_id: str) -> Tuple[str, str]:
        left = str(left_id or "").strip()
        right = str(right_id or "").strip()
        if not left or not right or left == right:
            raise ValueError("Pair decisions require two distinct article IDs.")
        return tuple(sorted((left, right)))

    def get_pair_decisions(self) -> Dict[Tuple[str, str], Dict[str, Any]]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT article_id_low, article_id_high, same_event, decided_by, "
                "decided_at, reason, confidence FROM pair_decisions"
            ).fetchall()
        return {
            (row[0], row[1]): {
                "same_event": bool(row[2]),
                "decided_by": row[3],
                "decided_at": row[4],
                "reason": row[5],
                "confidence": row[6],
            }
            for row in rows
        }

    def record_pair_decision(
        self,
        left_id: str,
        right_id: str,
        same_event: bool,
        decided_by: str = "auto",
        reason: str = "",
        confidence: Optional[float] = None,
    ) -> None:
        if decided_by not in {"auto", "human"}:
            raise ValueError("decided_by must be 'auto' or 'human'.")
        low_id, high_id = self._pair_ids(left_id, right_id)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO pair_decisions
                    (article_id_low, article_id_high, same_event, decided_by, reason, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(article_id_low, article_id_high) DO UPDATE SET
                    same_event = excluded.same_event,
                    decided_by = excluded.decided_by,
                    decided_at = CURRENT_TIMESTAMP,
                    reason = excluded.reason,
                    confidence = excluded.confidence
                """,
                (
                    low_id,
                    high_id,
                    int(bool(same_event)),
                    decided_by,
                    str(reason or ""),
                    confidence,
                ),
            )
            conn.commit()

    def get_sent_ledger(self, advisory_id: str) -> List[Dict[str, Any]]:
        advisory_id = str(advisory_id or "").strip()
        if not advisory_id:
            return []
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT recipient_team, sent_at, content_hash FROM sent_ledger "
                "WHERE advisory_id = ? ORDER BY sent_at",
                (advisory_id,),
            ).fetchall()
        return [
            {
                "recipient_team": row[0],
                "sent_at": row[1],
                "content_hash": row[2],
            }
            for row in rows
        ]

    def has_sent_content(
        self,
        advisory_id: str,
        recipient_team: str,
        content_hash: str,
    ) -> bool:
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT 1 FROM sent_ledger WHERE advisory_id = ? "
                "AND recipient_team = ? AND content_hash = ?",
                (
                    str(advisory_id or "").strip(),
                    str(recipient_team or "").strip(),
                    str(content_hash or "").strip(),
                ),
            ).fetchone()
        return row is not None

    def record_sent(
        self,
        advisory_id: str,
        recipient_team: str,
        sent_at: str,
        content_hash: str,
    ) -> bool:
        values = (
            str(advisory_id or "").strip(),
            str(recipient_team or "").strip(),
            str(sent_at or "").strip(),
            str(content_hash or "").strip(),
        )
        if not all(values):
            raise ValueError(
                "Sent-ledger entries require advisory_id, recipient_team, sent_at, and content_hash."
            )
        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO sent_ledger "
                "(advisory_id, recipient_team, sent_at, content_hash) VALUES (?, ?, ?, ?)",
                values,
            )
            conn.commit()
            return cursor.rowcount == 1
