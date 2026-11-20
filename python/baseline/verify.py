"""The baseline's own verifier. Exactly two checks, nothing else:

  B1 - chain links: every entry's hash, prev_hash link and signature are checked.
  B2 - anchor match: the latest value this baseline put on the chain still matches
       what the bundle holds for that same range.

Nobody else's evidence is ever consulted -- that is the whole point of a baseline,
and the whole limit of one: a single party who holds the signing key can rebuild its
own chain so that both of these checks still pass. See python/baseline/__init__.py.
"""
from nacl.signing import VerifyKey

from logsabha_core import verify_chain

MATCH = "MATCH"
MISMATCH = "MISMATCH"
CANNOT = "CANNOT VERIFY"
_ORDER = {MISMATCH: 0, CANNOT: 1, MATCH: 2}


def _norm(hex_text):
    text = str(hex_text).strip().lower()
    return text[2:] if text.startswith("0x") else text


def verify_baseline(bundle, reader, witness_id=None):
    """bundle: the dict loaded from a baseline evidence bundle (see export.py).
    reader: any verifier.chain.ChainReader (the SAME chain-reading code LogSabha's verifier
    uses -- reading the chain is shared infrastructure; nothing about the two checks is)."""
    witness_id = witness_id or bundle.get("witness_id") or "baseline"
    checks = []

    try:
        info = reader.witness_keys().get(witness_id)
    except Exception as err:
        return _finish([{"rule": "B1", "result": CANNOT, "detail": "the chain could not be read: %s" % err},
                        {"rule": "B2", "result": CANNOT, "detail": "the chain could not be read: %s" % err}])

    entries = [e for e in bundle.get("entries", []) if isinstance(e, dict)]
    if not info or not info.get("registered") or not info.get("public_key"):
        checks.append({"rule": "B1", "result": CANNOT, "detail":
                       "'%s' is not registered on the chain, so there is no key to check signatures against" % witness_id})
    elif not entries:
        checks.append({"rule": "B1", "result": CANNOT, "detail": "the bundle holds no entries"})
    else:
        pub = VerifyKey(bytes.fromhex(info["public_key"]))
        result = verify_chain(entries, pub)
        if result.valid:
            checks.append({"rule": "B1", "result": MATCH,
                          "detail": "%d entries; every hash, link and signature recomputed and checked" % len(entries)})
        else:
            checks.append({"rule": "B1", "result": MISMATCH, "detail": str(result.first_failure)})

    checks.append(_check_anchor(bundle, reader, witness_id, info, entries))
    return _finish(checks)


def _check_anchor(bundle, reader, witness_id, info, entries):
    """EVERY anchor on the baseline account is checked, not only the latest: the baseline never
    anchors a heartbeat (see core.py), so every anchor it ever made is a real, non-empty
    commitment to a specific entry's hash. Each one must still be a head that really appears in
    this log -- a later anchor matching is not allowed to excuse an earlier one that does not."""
    anchors = sorted((a for a in bundle.get("anchors", []) if isinstance(a, dict)), key=lambda a: a["batch_no"])
    if not anchors:
        return {"rule": "B2", "result": CANNOT, "detail": "nothing has been anchored yet"}
    if not info or not info.get("registered"):
        return {"rule": "B2", "result": CANNOT, "detail": "'%s' is not registered on the chain" % witness_id}
    try:
        chain_anchors = reader.anchors(witness_id, int(info.get("last_batch_no", 0)))
    except Exception as err:
        return {"rule": "B2", "result": CANNOT, "detail": "the chain could not be read: %s" % err}
    by_no = {a["batch_no"]: a for a in chain_anchors}
    by_seq = {e["seq"]: e for e in entries if isinstance(e, dict)}

    checked, mismatches = 0, []
    for a in anchors:
        on_chain = by_no.get(a["batch_no"])
        if on_chain is None:
            continue                                            # not yet on chain: nothing to compare for this one
        checked += 1
        if on_chain["last_seq"] < on_chain["first_seq"]:
            mismatches.append("batch %d: an empty (heartbeat) anchor is on chain for this witness, which this "
                              "baseline design should never produce" % a["batch_no"])
            continue
        tip = by_seq.get(on_chain["last_seq"])
        recomputed = tip.get("hash") if isinstance(tip, dict) else None
        wanted = _norm(on_chain["entries_root"])
        if recomputed is None:
            mismatches.append("batch %d: the entry at the anchored seq %d is missing from this log" % (
                a["batch_no"], on_chain["last_seq"]))
        elif _norm(recomputed) != wanted:
            mismatches.append("batch %d: the chain's anchored head (%s) no longer matches this log (%s now)" % (
                a["batch_no"], wanted[:12], _norm(recomputed)[:12]))

    if checked == 0:
        return {"rule": "B2", "result": CANNOT, "detail": "none of this log's anchors are on the chain yet"}
    if mismatches:
        return {"rule": "B2", "result": MISMATCH, "detail": "%d of %d anchors checked, OK; %s" % (
            checked - len(mismatches), checked, "; ".join(mismatches))}
    return {"rule": "B2", "result": MATCH,
            "detail": "%d anchor(s) checked, each one still a head that appears in this log" % checked}


def _finish(checks):
    overall = min((c["result"] for c in checks), key=lambda r: _ORDER[r])
    return {"overall": overall, "checks": checks}


def human_report(result, witness_id="baseline"):
    out = ["Baseline verification (single host, no peers, no receipts) - witness '%s'" % witness_id,
          "Overall: %s" % result["overall"], ""]
    for c in result["checks"]:
        out.append("%s %-14s %s" % (c["rule"], c["result"], c["detail"]))
    return "\n".join(out)
