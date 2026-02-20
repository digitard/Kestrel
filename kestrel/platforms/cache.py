"""
Kestrel - Local Program Cache

SQLite-backed cache for bug bounty programs and their scope data.
Enables offline access, fast lookups, and reduces API calls.
"""

import json
import sqlite3
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .models import Program, Platform, ScopeEntry


logger = logging.getLogger(__name__)


# Default cache location
DEFAULT_CACHE_DIR = Path.home() / ".kestrel"
DEFAULT_CACHE_DB = DEFAULT_CACHE_DIR / "programs.db"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS programs (
    id TEXT NOT NULL,
    handle TEXT NOT NULL,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    state TEXT DEFAULT 'unknown',
    offers_bounties INTEGER DEFAULT 0,
    managed INTEGER DEFAULT 0,
    url TEXT DEFAULT '',
    policy TEXT DEFAULT '',
    response_efficiency REAL DEFAULT 0.0,
    min_bounty REAL DEFAULT 0.0,
    max_bounty REAL DEFAULT 0.0,
    currency TEXT DEFAULT 'usd',
    created_at TEXT,
    updated_at TEXT,
    last_synced TEXT,
    raw_json TEXT DEFAULT '{}',
    PRIMARY KEY (platform, handle)
);

CREATE TABLE IF NOT EXISTS scope_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_platform TEXT NOT NULL,
    program_handle TEXT NOT NULL,
    asset_identifier TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    scope_status TEXT NOT NULL,
    instruction TEXT DEFAULT '',
    eligible_for_bounty INTEGER DEFAULT 1,
    max_severity TEXT DEFAULT '',
    FOREIGN KEY (program_platform, program_handle)
        REFERENCES programs(platform, handle)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scope_program
    ON scope_entries(program_platform, program_handle);

CREATE INDEX IF NOT EXISTS idx_scope_asset
    ON scope_entries(asset_identifier);

CREATE INDEX IF NOT EXISTS idx_programs_platform
    ON programs(platform);

CREATE INDEX IF NOT EXISTS idx_programs_bounty
    ON programs(offers_bounties);
"""


class ProgramCache:
    """
    SQLite-backed local cache for bug bounty program data.

    Provides:
      - Persistent storage of programs and scope
      - Fast local lookups without API calls
      - Staleness checking for cache invalidation
      - Platform-filtered queries

    Usage:
        cache = ProgramCache()  # Uses default path
        cache.upsert_program(program)
        cached = cache.get_program("hackerone", "security")
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_CACHE_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    @property
    def conn(self) -> sqlite3.Connection:
        """Lazy connection with WAL mode for concurrent reads."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _init_db(self):
        """Create tables if they don't exist."""
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    # ── Write Operations ────────────────────────────────────────────

    def upsert_program(self, program: Program) -> None:
        """
        Insert or update a program and its scope.

        Args:
            program: Program to cache
        """
        now = datetime.utcnow().isoformat()

        self.conn.execute("""
            INSERT OR REPLACE INTO programs
            (id, handle, name, platform, state, offers_bounties, managed,
             url, policy, response_efficiency, min_bounty, max_bounty,
             currency, created_at, updated_at, last_synced, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            program.id,
            program.handle,
            program.name,
            program.platform.value,
            program.state.value,
            int(bool(program.offers_bounties)),
            int(bool(program.managed)),
            program.url,
            program.policy,
            float(program.response_efficiency or 0.0),
            float(program.min_bounty or 0.0),
            float(program.max_bounty or 0.0),
            program.currency,
            program.created_at.isoformat() if program.created_at else None,
            program.updated_at.isoformat() if program.updated_at else None,
            now,
            json.dumps(program.raw_data),
        ))

        # Replace scope entries
        self.conn.execute("""
            DELETE FROM scope_entries
            WHERE program_platform = ? AND program_handle = ?
        """, (program.platform.value, program.handle))

        for entry in program.scope:
            self.conn.execute("""
                INSERT INTO scope_entries
                (program_platform, program_handle, asset_identifier,
                 asset_type, scope_status, instruction,
                 eligible_for_bounty, max_severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                program.platform.value,
                program.handle,
                entry.asset_identifier,
                entry.asset_type.value,
                entry.scope_status.value,
                entry.instruction,
                int(entry.eligible_for_bounty),
                entry.max_severity,
            ))

        self.conn.commit()

    def upsert_programs(self, programs: list[Program]) -> int:
        """
        Bulk upsert programs.

        Args:
            programs: List of programs to cache

        Returns:
            Number of programs cached
        """
        for program in programs:
            self.upsert_program(program)
        return len(programs)

    def delete_program(self, platform: str, handle: str) -> bool:
        """Delete a program and its scope from cache."""
        cursor = self.conn.execute("""
            DELETE FROM programs
            WHERE platform = ? AND handle = ?
        """, (platform, handle))
        self.conn.commit()
        return cursor.rowcount > 0

    # ── Read Operations ─────────────────────────────────────────────

    def get_program(self, platform: str, handle: str) -> Optional[Program]:
        """
        Get a cached program.

        Args:
            platform: Platform name (e.g., "hackerone")
            handle: Program handle

        Returns:
            Program or None if not cached
        """
        row = self.conn.execute("""
            SELECT * FROM programs
            WHERE platform = ? AND handle = ?
        """, (platform, handle)).fetchone()

        if not row:
            return None

        return self._row_to_program(row)

    def get_programs(
        self,
        platform: Optional[str] = None,
        offers_bounties: Optional[bool] = None,
        search: Optional[str] = None,
    ) -> list[Program]:
        """
        Query cached programs with optional filters.

        Args:
            platform: Filter by platform
            offers_bounties: Filter by bounty availability
            search: Search in handle and name

        Returns:
            List of matching programs
        """
        query = "SELECT * FROM programs WHERE 1=1"
        params = []

        if platform:
            query += " AND platform = ?"
            params.append(platform)

        if offers_bounties is not None:
            query += " AND offers_bounties = ?"
            params.append(int(offers_bounties))

        if search:
            query += " AND (handle LIKE ? OR name LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])

        query += " ORDER BY handle"

        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_program(row) for row in rows]

    def get_scope(self, platform: str, handle: str) -> list[ScopeEntry]:
        """Get scope entries for a cached program."""
        rows = self.conn.execute("""
            SELECT * FROM scope_entries
            WHERE program_platform = ? AND program_handle = ?
        """, (platform, handle)).fetchall()

        return [self._row_to_scope_entry(row) for row in rows]

    def search_scope(self, target: str) -> list[dict]:
        """
        Search all cached scope entries for a target.

        Useful for checking if a target appears in ANY program's scope.

        Args:
            target: Target to search for

        Returns:
            List of dicts with program and scope info
        """
        rows = self.conn.execute("""
            SELECT s.*, p.name as program_name, p.url as program_url
            FROM scope_entries s
            JOIN programs p ON s.program_platform = p.platform
                           AND s.program_handle = p.handle
            WHERE s.asset_identifier LIKE ?
            ORDER BY s.program_handle
        """, (f"%{target}%",)).fetchall()

        results = []
        for row in rows:
            results.append({
                "program_handle": row["program_handle"],
                "program_name": row["program_name"],
                "program_url": row["program_url"],
                "platform": row["program_platform"],
                "asset_identifier": row["asset_identifier"],
                "asset_type": row["asset_type"],
                "scope_status": row["scope_status"],
            })

        return results

    # ── Cache Management ────────────────────────────────────────────

    def is_stale(self, platform: str, handle: str, max_age_hours: int = 24) -> bool:
        """
        Check if a cached program is stale.

        Args:
            platform: Platform name
            handle: Program handle
            max_age_hours: Maximum cache age in hours

        Returns:
            True if stale or not cached
        """
        row = self.conn.execute("""
            SELECT last_synced FROM programs
            WHERE platform = ? AND handle = ?
        """, (platform, handle)).fetchone()

        if not row or not row["last_synced"]:
            return True

        synced = datetime.fromisoformat(row["last_synced"])
        age = datetime.utcnow() - synced
        return age > timedelta(hours=max_age_hours)

    def stats(self) -> dict:
        """Get cache statistics."""
        programs = self.conn.execute("SELECT COUNT(*) as c FROM programs").fetchone()
        scope = self.conn.execute("SELECT COUNT(*) as c FROM scope_entries").fetchone()

        by_platform = {}
        rows = self.conn.execute(
            "SELECT platform, COUNT(*) as c FROM programs GROUP BY platform"
        ).fetchall()
        for row in rows:
            by_platform[row["platform"]] = row["c"]

        return {
            "total_programs": programs["c"],
            "total_scope_entries": scope["c"],
            "by_platform": by_platform,
            "db_path": str(self.db_path),
        }

    def clear(self, platform: Optional[str] = None) -> int:
        """
        Clear cached data.

        Args:
            platform: If provided, only clear this platform's data

        Returns:
            Number of programs deleted
        """
        if platform:
            cursor = self.conn.execute(
                "DELETE FROM programs WHERE platform = ?", (platform,)
            )
        else:
            cursor = self.conn.execute("DELETE FROM programs")

        self.conn.commit()
        return cursor.rowcount

    # ── Internal Helpers ────────────────────────────────────────────

    def _row_to_program(self, row: sqlite3.Row) -> Program:
        """Convert a database row to a Program."""
        scope = self.get_scope(row["platform"], row["handle"])

        return Program(
            id=row["id"],
            handle=row["handle"],
            name=row["name"],
            platform=Platform(row["platform"]),
            state=_safe_enum(row["state"], "unknown"),
            offers_bounties=bool(row["offers_bounties"]),
            managed=bool(row["managed"]),
            scope=scope,
            url=row["url"],
            policy=row["policy"],
            response_efficiency=row["response_efficiency"],
            min_bounty=row["min_bounty"],
            max_bounty=row["max_bounty"],
            currency=row["currency"],
            created_at=_safe_datetime(row["created_at"]),
            updated_at=_safe_datetime(row["updated_at"]),
            last_synced=_safe_datetime(row["last_synced"]),
            raw_data=json.loads(row["raw_json"]) if row["raw_json"] else {},
        )

    @staticmethod
    def _row_to_scope_entry(row: sqlite3.Row) -> ScopeEntry:
        """Convert a database row to a ScopeEntry."""
        from .models import AssetType, ScopeStatus

        return ScopeEntry(
            asset_identifier=row["asset_identifier"],
            asset_type=AssetType(row["asset_type"]),
            scope_status=ScopeStatus(row["scope_status"]),
            instruction=row["instruction"],
            eligible_for_bounty=bool(row["eligible_for_bounty"]),
            max_severity=row["max_severity"],
        )

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


# ── Utility Functions ───────────────────────────────────────────────

def _safe_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse datetime string safely."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _safe_enum(value: str, default: str) -> "ProgramState":
    """Safely convert string to ProgramState."""
    from .models import ProgramState
    try:
        return ProgramState(value)
    except ValueError:
        return ProgramState(default)
