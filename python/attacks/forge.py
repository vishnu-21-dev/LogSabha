"""What someone who holds a witness's OWN signing key can do to its OWN database file.

This is the key-logic behind the "delete evidence" demonstration: given the witness's key
file and direct access to its SQLite database (root on that one machine), delete some entries
and make the rest of the chain perfectly self-consistent again -- every hash, every link,
every signature. It never touches another witness's key or data, and it never talks to the
chain (anchoring still happens, afterwards, through the normal witness process).

This is exactly the limit stated in logsabha_core/chain.py's own docstring: a key holder can
rebuild the WHOLE chain and it will still say VALID. Cross-witness checks (LogSabha's C1/C2)
are what catch this; a single witness's own chain check (I1, or the baseline's B1) cannot.
"""
import json
import sqlite3

from logsabha_core import GENESIS_PREV_HASH, entries_root_hex, entry_body, sign_batch_header, sign_entry

EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class ForgeError(Exception):
    pass


def delete_and_reseal(db_path, signing_key, drop_seqs):
    """Delete the given seq numbers from a witness's (or the baseline's) SQLite file, close the
    gap by renumbering every later entry, and re-sign everything that changed: the renumbered
    entries, and any batch header whose own entries_root or seq range depended on them (only a
    full witness has a batches table; the baseline has none, and this skips that step for it).
    Needs the database file to be quiet (the owning process should be stopped first).

    Returns {"dropped": [...], "renumbered": {old_seq: new_seq, ...}} for the entries that moved.
    """
    drop = set(drop_seqs)
    if not drop:
        raise ForgeError("nothing to drop")
    con = sqlite3.connect(str(db_path))
    try:
        rows = con.execute("SELECT seq, boot_id, entry_json, batch_no FROM entries ORDER BY seq").fetchall()
        if not rows:
            raise ForgeError("no entries in this database")
        con.execute("DELETE FROM entries")

        kept = [(seq, boot_id, json.loads(text), batch_no) for seq, boot_id, text, batch_no in rows if seq not in drop]
        if len(kept) == len(rows):
            raise ForgeError("none of the given seq numbers were found")

        mapping, rebuilt, prev, new_seq = {}, [], None, 0
        for old_seq, boot_id, entry, batch_no in kept:
            new_seq += 1
            mapping[old_seq] = new_seq
            body = entry_body(entry)
            body["seq"] = new_seq
            body["prev_hash"] = prev["hash"] if prev else GENESIS_PREV_HASH
            resigned = sign_entry(signing_key, body)
            prev = resigned
            rebuilt.append((new_seq, boot_id, resigned, batch_no))

        for new_seq, boot_id, entry, batch_no in rebuilt:
            con.execute("INSERT INTO entries(seq, boot_id, entry_json, batch_no) VALUES(?,?,?,?)",
                       (new_seq, boot_id, json.dumps(entry), batch_no))

        by_new_seq = {e["seq"]: e for _, _, e, _ in rebuilt}
        by_batch = {}
        for new_seq, _, _, batch_no in rebuilt:
            if batch_no is None:
                continue
            lo, hi = by_batch.get(batch_no, (new_seq, new_seq))
            by_batch[batch_no] = (min(lo, new_seq), max(hi, new_seq))

        has_batches = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='batches'").fetchone()
        new_tail = 0
        for batch_no, header_text in (con.execute("SELECT batch_no, header_json FROM batches ORDER BY batch_no").fetchall()
                                      if has_batches else []):
            header = json.loads(header_text)
            span = by_batch.get(batch_no)
            if span is None:
                if header["last_seq"] >= header["first_seq"]:
                    raise ForgeError("batch %d would be left empty by this drop; not supported here" % batch_no)
                new_first, new_last, entries_root = new_tail + 1, new_tail, EMPTY_ROOT
            else:
                new_first, new_last = span
                entries_root = entries_root_hex([by_new_seq[s] for s in range(new_first, new_last + 1)])
            new_tail = new_last
            if (new_first, new_last) == (header["first_seq"], header["last_seq"]):
                continue                                           # this batch was not touched at all
            body = {k: v for k, v in header.items() if k != "sig"}
            body.update(first_seq=new_first, last_seq=new_last, entries_root=entries_root)
            con.execute("UPDATE batches SET header_json=?, first_seq=?, last_seq=? WHERE batch_no=?",
                       (json.dumps(sign_batch_header(signing_key, body)), new_first, new_last, batch_no))
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    moved = {old: new for old, new in mapping.items() if old != new}
    return {"dropped": sorted(drop), "renumbered": moved}
