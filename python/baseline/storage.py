"""Durable storage for the baseline: one SQLite file, two small tables.

Much smaller than a witness's storage (witness/storage.py): no peers, no receipts, no
authenticators, no anchor queue. Just the entries and what has been anchored so far.
"""
import json
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries(
    seq INTEGER PRIMARY KEY,
    boot_id TEXT NOT NULL,                    -- same column layout as a witness's entries table, on purpose:
    entry_json TEXT NOT NULL,                 -- attacks/forge.py works unchanged against either one
    batch_no INTEGER);                        -- NULL until an anchor covers it

CREATE TABLE IF NOT EXISTS anchors(
    batch_no INTEGER PRIMARY KEY,
    first_seq INTEGER NOT NULL,
    last_seq INTEGER NOT NULL,                -- empty anchor (heartbeat): last_seq = first_seq - 1
    entries_root TEXT NOT NULL,                -- the hash-chain head at this point, not a Merkle root
    tx_hash TEXT,
    created_at REAL NOT NULL);
"""


class Storage:
    def __init__(self, path):
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._lock = threading.Lock()
        self._db.executescript(SCHEMA)

    def close(self):
        with self._lock:
            self._db.close()

    def add_entry(self, entry):
        with self._lock:
            self._db.execute("BEGIN")
            self._db.execute("INSERT INTO entries(seq, boot_id, entry_json, batch_no) VALUES(?,?,?,NULL)",
                             (entry["seq"], entry["boot_id"], json.dumps(entry)))
            self._db.execute("COMMIT")

    def last_entry(self):
        with self._lock:
            row = self._db.execute("SELECT entry_json FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def all_entries(self):
        with self._lock:
            rows = self._db.execute("SELECT entry_json FROM entries ORDER BY seq").fetchall()
        return [json.loads(r[0]) for r in rows]

    def insert_anchor(self, batch_no, first_seq, last_seq, entries_root, tx_hash, created_at):
        with self._lock:
            self._db.execute("BEGIN")
            self._db.execute(
                "INSERT INTO anchors(batch_no, first_seq, last_seq, entries_root, tx_hash, created_at) "
                "VALUES(?,?,?,?,?,?)", (batch_no, first_seq, last_seq, entries_root, tx_hash, created_at))
            if last_seq >= first_seq:
                self._db.execute("UPDATE entries SET batch_no=? WHERE seq BETWEEN ? AND ?",
                                 (batch_no, first_seq, last_seq))
            self._db.execute("COMMIT")

    def last_anchor(self):
        with self._lock:
            row = self._db.execute(
                "SELECT batch_no, first_seq, last_seq, entries_root, tx_hash, created_at "
                "FROM anchors ORDER BY batch_no DESC LIMIT 1").fetchone()
        if row is None:
            return None
        keys = ("batch_no", "first_seq", "last_seq", "entries_root", "tx_hash", "created_at")
        return dict(zip(keys, row))

    def all_anchors(self):
        with self._lock:
            rows = self._db.execute(
                "SELECT batch_no, first_seq, last_seq, entries_root, tx_hash, created_at "
                "FROM anchors ORDER BY batch_no").fetchall()
        keys = ("batch_no", "first_seq", "last_seq", "entries_root", "tx_hash", "created_at")
        return [dict(zip(keys, r)) for r in rows]


def read_only_snapshot(db_path):
    """A plain dict read of everything, for export. Does not need the live Storage lock."""
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError("no such database file")
    con = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10)
    try:
        con.execute("BEGIN")
        entries = [json.loads(r[0]) for r in con.execute("SELECT entry_json FROM entries ORDER BY seq")]
        keys = ("batch_no", "first_seq", "last_seq", "entries_root", "tx_hash", "created_at")
        anchors = [dict(zip(keys, r)) for r in con.execute(
            "SELECT batch_no, first_seq, last_seq, entries_root, tx_hash, created_at FROM anchors ORDER BY batch_no")]
        con.execute("COMMIT")
    finally:
        con.close()
    return entries, anchors
