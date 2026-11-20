"""The baseline's evidence bundle: one small JSON file. Much smaller than a LogSabha bundle:
just the entries and what has been anchored. No keys, no personal data.

  python -m baseline export --db <path> --witness-id baseline --out bundle.json
"""
import json
from datetime import datetime, timezone

from .storage import read_only_snapshot

BUNDLE_FORMAT = "logsabha-baseline-bundle"
BUNDLE_VERSION = 1


def build_bundle(db_path, witness_id="baseline"):
    entries, anchors = read_only_snapshot(db_path)
    return {
        "format": BUNDLE_FORMAT, "version": BUNDLE_VERSION, "witness_id": witness_id,
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z",
        "entries": entries, "anchors": anchors,
    }


def write_bundle(db_path, out_path, witness_id="baseline"):
    bundle = build_bundle(db_path, witness_id)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
    return bundle
