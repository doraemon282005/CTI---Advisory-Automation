import sqlite3
from pathlib import Path
from typing import List, Dict, Any

class AdvisoryCacheDB:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
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
            conn.commit()

    def is_seen(self, article_id: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM processed_advisories WHERE article_id = ?", (article_id,))
            return cursor.fetchone() is not None

    def mark_seen(self, article_id: str, title: str, source: str, matched_app: str, severity: str, timestamp: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO processed_advisories 
                (article_id, title, source, matched_app, severity, first_seen_ts)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (article_id, title, source, matched_app, severity, timestamp))
            conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM processed_advisories")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT severity, COUNT(*) FROM processed_advisories GROUP BY severity")
            breakdown = dict(cursor.fetchall())
            return {"total_tracked": total, "by_severity": breakdown}
