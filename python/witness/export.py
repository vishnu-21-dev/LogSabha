"""Evidence bundle export: one JSON file holding what ONE witness knows.

It is built from the witness database, read-only. It never holds a private key, a key file
path, or any personal data (entries only carry counts, sizes, destinations and request ids).

  python -m witness export --db <path> --out bundle.json
"""
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

BUNDLE_FORMAT = "logsabha-evidence-bundle"
BUNDLE_VERSION = 1
TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")


def _open_read_only(db_path):
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError("no such database file")
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10)


def build_bundle(db_path):
    con = _open_read_only(db_path)
    try:
        con.execute("BEGIN")                       # one consistent snapshot
        meta = dict(con.execute("SELECT key, value FROM meta").fetchall())
        if "witness_id" not in meta:
            raise ValueError("this database has no witness identity (was it ever started?)")

        entries = [json.loads(r[0]) for r in con.execute("SELECT entry_json FROM entries ORDER BY seq")]
        batches = [{"batch_no": r[0], "created_at": r[2], "header": json.loads(r[1])}
                   for r in con.execute("SELECT batch_no, header_json, created_at FROM batches ORDER BY batch_no")]

        windows = []
        for r in con.execute(
                "SELECT w.window_no, w.first_batch, w.last_batch, w.first_seq, w.last_seq, w.entries_root, "
                "w.receipts_root, w.policy_hash, w.created_at, q.state, q.ref "
                "FROM windows w LEFT JOIN anchor_queue q USING(window_no) ORDER BY w.window_no"):
            windows.append({
                "window_no": r[0], "first_batch": r[1], "last_batch": r[2], "first_seq": r[3], "last_seq": r[4],
                "entries_root": r[5], "receipts_root": r[6], "policy_hash": r[7], "created_at": r[8],
                "queue_state": r[9], "tx_hash": r[10] if r[10] and TX_HASH.match(r[10]) else None})

        issued = [{"order": r[0], "included_in_batch": r[1], "receipt_hash": r[2], "receipt": json.loads(r[3])}
                  for r in con.execute("SELECT id, included_in_batch, receipt_hash, receipt_json FROM receipts "
                                       "WHERE kind='issued' ORDER BY id")]
        received = [{"peer": r[0], "source_batch": r[1], "receipt_hash": r[2], "receipt": json.loads(r[3])}
                    for r in con.execute("SELECT peer, source_batch, receipt_hash, receipt_json FROM receipts "
                                         "WHERE kind='received' ORDER BY id")]
        authenticators = [json.loads(r[0]) for r in con.execute(
            "SELECT auth_json FROM authenticators ORDER BY witness_id, seq")]
        peer_headers = [{"from_witness": r[0], "batch_no": r[1], "header": json.loads(r[2]), "received_at": r[3]}
                        for r in con.execute("SELECT from_witness, batch_no, header_json, received_at "
                                             "FROM peer_headers ORDER BY from_witness, batch_no")]
        conflicting = [{"from_witness": r[0], "batch_no": r[1], "header": json.loads(r[2]), "received_at": r[3]}
                       for r in con.execute("SELECT from_witness, batch_no, header_json, received_at "
                                            "FROM conflicting_headers ORDER BY id")]
        con.execute("COMMIT")
    finally:
        con.close()

    return {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "witness_id": meta["witness_id"],
        "role": meta.get("role"),
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entries": entries,
        "markers": [e for e in entries if e.get("event_type") in ("restart", "shutdown")],
        "batches": batches,
        "windows": windows,
        "receipts_issued": issued,
        "receipts_received": received,
        "authenticators": authenticators,
        "peer_headers": peer_headers,
        "conflicting_headers": conflicting,
    }


def write_bundle(db_path, out_path):
    bundle = build_bundle(db_path)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=1, sort_keys=True)
    return bundle


def export_main(argv):
    import argparse
    p = argparse.ArgumentParser(prog="witness export", description="Write an evidence bundle from a witness database")
    p.add_argument("--db", required=True, help="the witness SQLite file (read only; the witness may keep running)")
    p.add_argument("--out", required=True, help="bundle file to write (JSON)")
    args = p.parse_args(argv)
    try:
        bundle = write_bundle(args.db, args.out)
    except (OSError, ValueError, sqlite3.Error) as err:
        print("error: cannot export: %s" % (err,), file=sys.stderr)
        return 2
    print("wrote %s: witness %s, %d entries, %d anchor windows" % (
        args.out, bundle["witness_id"], len(bundle["entries"]), len(bundle["windows"])))
    return 0
