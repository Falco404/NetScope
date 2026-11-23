"""Store package: SQLite persistence with scan history + diff (M5).

Database path comes from the NETSCOPE_DB env var (gitignored file, no secrets
in the repo). See netscope.store.store for SQLiteStore.
"""

from netscope.store.store import ScanDiff, ScanSummary, SQLiteStore, db_path

__all__ = ["ScanDiff", "ScanSummary", "SQLiteStore", "db_path"]
