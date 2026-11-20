"""The integrity rules I1 to I7.

Verdicts are only MATCH, MISMATCH or CANNOT VERIFY. Two promises hold everywhere:
  - missing evidence is never MATCH;
  - silence (a peer or witness we have no evidence from) is CANNOT VERIFY, never MISMATCH.

Public keys and anchors come from the chain reader. A key written inside a bundle is never used.
"""
import re
from bisect import bisect_left, bisect_right

from nacl.signing import VerifyKey

from logsabha_core import (
    ENTRY_FIELDS, GENESIS_PREV_HASH, canonical_json, compute_entry_hash, merkle_root, sha256,
    verify_authenticator, verify_batch_header, verify_entry_signature, verify_receipt,
)

from .chain import EMPTY_ROOT, ChainError, hex_root
from .model import (
    CANNOT, MATCH, MISMATCH, RULES, BundleError, Finding, display, load_bundle, witness_sort_key, worst,
)

TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

LIMITS = {
    "I1": "Looks only inside this bundle. Someone who holds the witness's own key could rebuild a whole chain "
          "that passes this rule; I3 (the chain) and I5 (the other witnesses) are what catch that.",
    "I2": "Says who signed, not whether the signed content is true. Keys come from the chain, never from a bundle.",
    "I3": "Only windows already anchored on the chain are compared. Entries newer than the last anchor are "
          "covered by I5 until they are anchored. The bundle must have been exported after the anchor was made.",
    "I4": "Cannot see newest entries that were removed from the very end; I3 and I5 look for that. "
          "A signed restart marker can explain a gap, but the missing entries are still checked by I3 and I5.",
    "I5": "Only the bundles supplied are searched. A forger can write a later time on a forged entry to look like "
          "no peer was reachable, which makes the result CANNOT VERIFY instead of MISMATCH. "
          "The newest entries after the last peer exchange cannot have been authenticated yet.",
    "I6": "Only receipts in windows already anchored are checked; later ones wait for their window. "
          "Receipts held by a witness whose bundle was not supplied cannot be seen.",
    "I7": "Only headers found in the supplied bundles are compared.",
}


def runs(values):
    """[3,4,5,9] -> [(3,5),(9,9)]"""
    out = []
    for v in sorted(set(values)):
        if out and v == out[-1][1] + 1:
            out[-1] = (out[-1][0], v)
        else:
            out.append((v, v))
    return out


def seq_text(lo, hi):
    return "seq %d" % lo if lo == hi else "seq %d-%d" % (lo, hi)


def brief(items, limit=4):
    items = list(items)
    if len(items) <= limit:
        return "; ".join(items)
    return "; ".join(items[:limit]) + "; and %d more" % (len(items) - limit)


def short(hex_text):
    return str(hex_text)[:12] + ("..." if len(str(hex_text)) > 12 else "")


def receipt_hash_of(receipt):
    try:
        return sha256(canonical_json(receipt)).hex()
    except (TypeError, ValueError):
        return None


class Run:
    """Everything one verification run knows. Built once, used by every rule."""

    def __init__(self, bundles, reader):
        self.reader = reader
        self.bundles = bundles                      # {witness_id: Bundle}
        self.chain_error = None
        self.keys = {}                              # {witness_id: VerifyKey or None}
        self.registered = []                        # witness ids registered on the chain
        self.chain_info = {}
        self.anchors = {}                           # {witness_id: [anchor dict]} or None if unreadable
        self.anchor_error = {}
        self.findings = []
        self.notices = []
        self._valid_receipts = None

    # ---------------------------------------------------------------- chain
    def load_chain(self):
        try:
            info = self.reader.witness_keys()
        except ChainError as err:
            self.chain_error = str(err)
            return
        self.chain_info = info
        self.registered = sorted((n for n, w in info.items() if w.get("registered")), key=witness_sort_key)
        for name in self.registered:
            pub = info[name].get("public_key")
            try:
                self.keys[name] = VerifyKey(bytes.fromhex(pub)) if pub else None
            except (ValueError, TypeError):
                self.keys[name] = None
            try:
                self.anchors[name] = self.reader.anchors(name, int(info[name].get("last_batch_no", 0)))
            except ChainError as err:
                self.anchors[name] = None
                self.anchor_error[name] = str(err)

    def subjects(self):
        """The witnesses to check: everyone registered on the chain, or (chain unreadable) whoever sent a bundle."""
        if self.chain_error:
            return sorted(self.bundles, key=witness_sort_key)
        return list(self.registered)

    def bundle(self, w):
        return self.bundles.get(w)

    def peers_of(self, w):
        return [p for p in self.subjects() if p != w]

    # ------------------------------------------------------------- findings
    def add(self, rule, result, subject, statement, code="", seq=None, evidence=(), limitation=None,
            tx=None, witnesses=None, time_range=None):
        b = self.bundles.get(subject)
        f = Finding(
            rule=rule, result=result, subject=subject, statement=statement, code=code,
            witnesses=witnesses or [subject], seq_range=seq,
            time_range=time_range or (self.time_range(b, *seq) if seq else "n/a"),
            evidence=list(evidence), limitation=limitation if limitation is not None else LIMITS.get(rule, ""),
            anchor_tx=tx, answerable_by=display(subject) + " operator")
        self.findings.append(f)
        return f

    def cannot_without_bundle(self, rule, w, what):
        return self.add(rule, CANNOT, w, "No evidence bundle was supplied for the %s, so %s cannot be checked." % (
            display(w), what), code="no-bundle",
            evidence=["no bundle file was given for witness '%s'" % w],
            limitation="Missing evidence is never counted as a match. Supply this witness's bundle to check it.")

    def chain_unreadable(self, rule, w, what):
        return self.add(rule, CANNOT, w, "The chain could not be read, so %s cannot be checked." % what,
                        code="no-chain", evidence=["chain: %s" % self.chain_error],
                        limitation="Public keys and anchors come only from the chain.")

    def time_range(self, b, lo, hi):
        if b is None or lo is None:
            return "n/a"
        seqs = sorted(b.by_seq)
        i, j = bisect_left(seqs, lo), bisect_right(seqs, hi)
        if i >= j:
            return seq_text(lo, hi)
        first, last = b.by_seq[seqs[i]].get("ts_utc"), b.by_seq[seqs[j - 1]].get("ts_utc")
        return "%s to %s (%s)" % (first, last, seq_text(lo, hi)) if first and last else seq_text(lo, hi)

    # -------------------------------------------------------------- receipts
    def valid_receipts(self):
        """{hash: receipt} of every receipt, in any bundle, whose signature verifies under its recipient's chain key."""
        if self._valid_receipts is None:
            out = {}
            for b in self.bundles.values():
                for item in list(b.receipts_issued) + list(b.receipts_received):
                    r = item.get("receipt") if isinstance(item, dict) else None
                    key = self.keys.get(r.get("recipient")) if isinstance(r, dict) else None
                    h = receipt_hash_of(r) if isinstance(r, dict) else None
                    if key is not None and h and verify_receipt(key, r):
                        out[h] = r
            self._valid_receipts = out
        return self._valid_receipts

    def window_receipts(self, w):
        """{window_no: (hashes in issue order, problems)} rebuilt from W's own bundle."""
        b = self.bundles[w]
        wins = {x.get("window_no"): x for x in b.windows if isinstance(x, dict)}
        issued = []
        for item in sorted((i for i in b.receipts_issued if isinstance(i, dict)), key=lambda i: i.get("order", 0)):
            r = item.get("receipt")
            h = receipt_hash_of(r) if isinstance(r, dict) else None
            issued.append((h, r, item))
        return wins, issued


# ====================================================================== I1
def rule_i1(run, w):
    b = run.bundle(w)
    if b is None:
        return run.cannot_without_bundle("I1", w, "its chain links and hashes")
    problems, prev = [], None
    ordered = sorted((e for e in b.entries if isinstance(e, dict) and isinstance(e.get("seq"), int)),
                     key=lambda e: e["seq"])
    unreadable = len(b.entries) - len(ordered)
    for e in ordered:
        seq = e["seq"]
        missing = [f for f in ENTRY_FIELDS if f not in e]
        if missing:
            problems.append((seq, "malformed", "seq %d is missing fields: %s" % (seq, ", ".join(missing))))
            prev = None
            continue
        try:
            recomputed = compute_entry_hash(e)
        except (TypeError, ValueError):
            problems.append((seq, "malformed", "seq %d cannot be hashed" % seq))
            prev = None
            continue
        if recomputed != e["hash"]:
            problems.append((seq, "hash", "seq %d: stored hash %s, recomputed from its content %s (content was changed)"
                             % (seq, short(e["hash"]), short(recomputed))))
        if e["witness_id"] != w:
            problems.append((seq, "witness", "seq %d says it belongs to '%s'" % (seq, e["witness_id"])))
        if prev is not None and seq == prev["seq"] + 1:
            if e["prev_hash"] != prev["hash"]:
                problems.append((seq, "link", "seq %d: prev_hash %s is not the hash of seq %d (%s)"
                                 % (seq, short(e["prev_hash"]), prev["seq"], short(prev["hash"]))))
        elif prev is None and seq == 1 and e["prev_hash"] != GENESIS_PREV_HASH:
            problems.append((seq, "link", "seq 1 does not start from the all-zero genesis hash"))
        prev = e
    if unreadable:
        problems.append((None, "malformed", "%d entries have no usable seq number" % unreadable))

    if problems:
        by_code = {}
        for seq, code, text in problems:
            by_code.setdefault(code, []).append((seq, text))
        labels = {"hash": "the content of an entry no longer matches its hash",
                  "link": "an entry does not link to the entry before it",
                  "malformed": "an entry is malformed", "witness": "an entry names a different witness"}
        for code, items in by_code.items():
            seqs = [s for s, _ in items if s is not None]
            for lo, hi in (runs(seqs) or [(None, None)]):
                texts = [t for s, t in items if s is None or lo <= s <= hi]
                run.add("I1", MISMATCH, w, "%s: %s." % (display(w), labels[code]) if lo is None else
                        "%s: %s at %s." % (display(w), labels[code], seq_text(lo, hi)),
                        code=code, seq=(lo, hi) if lo is not None else None, evidence=texts[:6])
        return
    if not ordered:
        run.add("I1", CANNOT, w, "The %s bundle holds no entries, so there is nothing to check." % display(w),
                code="empty", evidence=["entries: 0"])
        return
    run.add("I1", MATCH, w, "%s: all %d entries hash correctly and link to the one before." % (display(w), len(ordered)),
            code="ok", seq=(ordered[0]["seq"], ordered[-1]["seq"]),
            evidence=["%d entries, seq %d-%d, every hash recomputed from content" % (
                len(ordered), ordered[0]["seq"], ordered[-1]["seq"])])


# ====================================================================== I2
def rule_i2(run, w):
    b = run.bundle(w)
    if b is None:
        return run.cannot_without_bundle("I2", w, "its signatures")
    if run.chain_error:
        return run.chain_unreadable("I2", w, "signatures")
    key = run.keys.get(w)
    bad, unchecked, checked = {}, [], 0

    def check(kind, locator, signer, fn, item):
        nonlocal checked
        vk = run.keys.get(signer)
        if vk is None:
            unchecked.append("%s %s: signer '%s' has no registered key on the chain" % (kind, locator, signer))
            return
        checked += 1
        try:
            ok = bool(fn(vk, item))
        except (TypeError, ValueError, KeyError):
            ok = False
        if not ok:
            bad.setdefault(kind, []).append((locator, signer))

    if key is None:
        unchecked.append("witness '%s' has no registered key on the chain" % w)
    else:
        for e in b.entries:
            if isinstance(e, dict) and isinstance(e.get("seq"), int):
                check("entry", e["seq"], w, verify_entry_signature, e)
    for item in b.batches:
        h = item.get("header") if isinstance(item, dict) else None
        if isinstance(h, dict):
            check("batch header", "batch %s" % h.get("batch_no"), w, verify_batch_header, h)
    for item in b.receipts_issued:
        r = item.get("receipt") if isinstance(item, dict) else None
        if isinstance(r, dict):
            check("receipt issued", "for %s batch %s" % (r.get("source"), r.get("source_batch")), w, verify_receipt, r)
    for item in b.receipts_received:
        r = item.get("receipt") if isinstance(item, dict) else None
        if isinstance(r, dict):
            check("receipt received", "from %s for batch %s" % (r.get("recipient"), r.get("source_batch")),
                  r.get("recipient"), verify_receipt, r)
    for a in b.authenticators:
        if isinstance(a, dict):
            check("authenticator", "of %s seq %s" % (a.get("witness_id"), a.get("seq")), a.get("witness_id"),
                  verify_authenticator, a)
    for kind, lst in (("peer header", b.peer_headers), ("conflicting header", b.conflicting_headers)):
        for item in lst:
            h = item.get("header") if isinstance(item, dict) else None
            if isinstance(h, dict):
                check(kind, "from %s batch %s" % (item.get("from_witness"), h.get("batch_no")),
                      item.get("from_witness"), verify_batch_header, h)

    for kind, items in bad.items():
        if kind == "entry":
            for lo, hi in runs([loc for loc, _ in items]):
                run.add("I2", MISMATCH, w, "%s: the signature on an entry does not verify under the on-chain key at %s." % (
                    display(w), seq_text(lo, hi)), code="entry", seq=(lo, hi),
                    evidence=["on-chain key of '%s' is %s" % (w, short(run.chain_info[w]["public_key"])),
                              "signature check failed for %s" % seq_text(lo, hi)])
        else:
            who = sorted({s for _, s in items if s})
            run.add("I2", MISMATCH, w, "%s: %d %s signature(s) do not verify under the on-chain key of %s." % (
                display(w), len(items), kind, ", ".join(display(x) for x in who)),
                code=kind.replace(" ", "-"), witnesses=[w] + [x for x in who if x != w],
                evidence=[brief(str(loc) for loc, _ in items)])
    if unchecked and not bad:
        run.add("I2", CANNOT, w, "%s: some signatures could not be checked because no on-chain key was found." % display(w),
                code="no-key", evidence=unchecked[:6])
    elif unchecked:
        run.add("I2", CANNOT, w, "%s: some other signatures could not be checked (no on-chain key)." % display(w),
                code="no-key", evidence=unchecked[:6])
    if not bad and not unchecked:
        if checked:
            run.add("I2", MATCH, w, "%s: all %d signatures in the bundle verify under the on-chain keys." % (display(w), checked),
                    code="ok", evidence=["%d signatures checked (entries, batch headers, receipts, authenticators, peer headers)" % checked])
        else:
            run.add("I2", CANNOT, w, "%s: the bundle holds nothing signed to check." % display(w), code="empty")


# ====================================================================== I4
def rule_i4(run, w):
    b = run.bundle(w)
    if b is None:
        return run.cannot_without_bundle("I4", w, "its sequence numbers")
    entries = [e for e in b.entries if isinstance(e, dict) and isinstance(e.get("seq"), int)]
    if not entries:
        run.add("I4", CANNOT, w, "The %s bundle holds no entries, so there is no sequence to check." % display(w), code="empty")
        return
    key = run.keys.get(w)
    seen, dups = {}, []
    for e in entries:
        if e["seq"] in seen:
            dups.append(e["seq"])
        seen.setdefault(e["seq"], e)
    seqs = sorted(seen)

    def signed_restart(e):
        return e.get("event_type") == "restart" and key is not None and verify_entry_signature(key, e)

    markers = [seen[s] for s in seqs if seen[s].get("event_type") == "restart"]
    notices = ["restart marker at seq %d: %s (boot %s, %s)" % (
        m["seq"], m.get("result"), str(m.get("boot_id"))[:8], m.get("ts_utc")) for m in markers]
    gaps, explained = [], []
    expect = 1
    for s in seqs:
        if s > expect:
            if signed_restart(seen[s]):
                explained.append((expect, s - 1, s))
            else:
                gaps.append((expect, s - 1))
        expect = s + 1

    for lo, hi, at in explained:
        notices.append("gap %s is covered by the signed restart marker at seq %d (%s)" % (
            seq_text(lo, hi), at, seen[at].get("result")))
    for n in notices:
        run.notices.append("%s: %s" % (display(w), n))

    if gaps or dups:
        for lo, hi in gaps:
            run.add("I4", MISMATCH, w, "%s: entries are missing at %s and no signed restart marker explains it." % (
                display(w), seq_text(lo, hi)), code="gap", seq=(lo, hi),
                evidence=["%d entries missing between seq %d and seq %d" % (hi - lo + 1, lo - 1, hi + 1)])
        for s in sorted(set(dups)):
            run.add("I4", MISMATCH, w, "%s: seq %d appears more than once." % (display(w), s), code="duplicate",
                    seq=(s, s), evidence=["two entries share seq %d" % s])
        return
    run.add("I4", MATCH, w, "%s: seq %d-%d has no unexplained gaps%s." % (
        display(w), seqs[0], seqs[-1],
        "" if not explained else " (%d gap(s) covered by a signed restart marker)" % len(explained)),
        code="ok", seq=(seqs[0], seqs[-1]),
        evidence=["%d entries" % len(seqs)] + notices[:6])


# ====================================================================== I3
def _anchor_label(a):
    return "window %d (%s)" % (a["batch_no"], "heartbeat, no entries" if a["last_seq"] < a["first_seq"]
                               else seq_text(a["first_seq"], a["last_seq"]))


def window_receipt_root(run, w, win):
    """Rebuild a window's receipts root from W's own bundle. Returns (root_hex or None, hashes, problem)."""
    b = run.bundle(w)
    first, last = win.get("first_batch"), win.get("last_batch")
    if not isinstance(first, int) or not isinstance(last, int):
        return None, [], "the window record has no batch range"
    hashes = []
    for item in sorted((i for i in b.receipts_issued if isinstance(i, dict)), key=lambda i: i.get("order", 0)):
        r = item.get("receipt")
        if not isinstance(r, dict):
            continue
        rb = r.get("recipient_batch")
        if isinstance(rb, int) and first <= rb <= last:
            h = receipt_hash_of(r)
            if h is None:
                return None, [], "a receipt cannot be hashed"
            hashes.append(h)
    return merkle_root([bytes.fromhex(h) for h in hashes]).hex(), hashes, None


def rule_i3(run, w):
    b = run.bundle(w)
    if run.chain_error:
        return run.chain_unreadable("I3", w, "anchors")
    anchors = run.anchors.get(w)
    if anchors is None:
        return run.add("I3", CANNOT, w, "The anchors of the %s could not be read from the chain." % display(w),
                       code="no-chain", evidence=["chain: %s" % run.anchor_error.get(w)])
    if b is None:
        last = anchors[-1] if anchors else None
        return run.add("I3", CANNOT, w, "No evidence bundle was supplied for the %s, but the chain holds %d anchored "
                       "window(s) for it, so they cannot be compared." % (display(w), len(anchors)), code="no-bundle",
                       tx=last["tx_hash"] if last else None,
                       evidence=["chain anchors: %d%s" % (len(anchors), (", newest covers %s" % seq_text(
                           last["first_seq"], last["last_seq"])) if last and last["last_seq"] >= last["first_seq"] else "")],
                       limitation="Missing evidence is never counted as a match. Supply this witness's bundle to check it.")
    if not anchors:
        return run.add("I3", CANNOT, w, "The chain holds no anchors for the %s yet, so there is nothing to compare." %
                       display(w), code="no-anchors", evidence=["chain anchors: 0"])

    wins = {x.get("window_no"): x for x in b.windows if isinstance(x, dict)}
    batches = {}
    for item in b.batches:
        h = item.get("header") if isinstance(item, dict) else None
        if isinstance(h, dict) and isinstance(h.get("batch_no"), int):
            batches[h["batch_no"]] = h
    ok_windows, bad_any = 0, False
    for a in anchors:
        label, problems = _anchor_label(a), []
        lo, hi = a["first_seq"], a["last_seq"]
        heartbeat = hi < lo
        # entries root, recomputed from the entries in the bundle, selected by the CHAIN's seq range
        if heartbeat:
            if a["entries_root"] != EMPTY_ROOT:
                problems.append(("entries", "the chain says this window is empty but its root is not the empty root"))
        else:
            missing = [s for s in range(lo, hi + 1) if s not in b.by_seq]
            if missing:
                mr = runs(missing)
                problems.append(("missing", "the chain says %s existed; the bundle is missing %s" % (
                    seq_text(lo, hi), ", ".join(seq_text(x, y) for x, y in mr[:4]))))
            else:
                try:
                    root = merkle_root([bytes.fromhex(b.by_seq[s]["hash"]) for s in range(lo, hi + 1)]).hex()
                except (KeyError, ValueError, TypeError):
                    root = None
                if root != a["entries_root"]:
                    problems.append(("entries", "entriesRoot recomputed from the bundle is %s, the chain holds %s" % (
                        short(root), short(a["entries_root"]))))
        # receipts root, recomputed from the receipts the witness issued in that window
        win = wins.get(a["batch_no"])
        if win is None:
            problems.append(("window", "the chain anchored window %d but the bundle has no record of that window" % a["batch_no"]))
        else:
            if win.get("first_seq") != lo or win.get("last_seq") != hi:
                problems.append(("window", "the bundle describes window %d as %s-%s, the chain as %s-%s" % (
                    a["batch_no"], win.get("first_seq"), win.get("last_seq"), lo, hi)))
            hf, hl = batches.get(win.get("first_batch")), batches.get(win.get("last_batch"))
            if hf is None or hl is None:
                problems.append(("window", "the signed batch headers for window %d are not in the bundle" % a["batch_no"]))
            elif hf.get("first_seq") != lo or hl.get("last_seq") != hi:
                problems.append(("window", "window %d does not line up with its signed batch headers (headers say %s-%s)" % (
                    a["batch_no"], hf.get("first_seq"), hl.get("last_seq"))))
            root, hashes, why = window_receipt_root(run, w, win)
            if why:
                problems.append(("receipts", why))
            elif root != a["receipts_root"]:
                problems.append(("receipts", "receiptsRoot recomputed from %d receipt(s) in the bundle is %s, the chain holds %s" % (
                    len(hashes), short(root), short(a["receipts_root"]))))
        if problems:
            bad_any = True
            kinds = sorted({k for k, _ in problems})
            what = {"missing": "entries for an anchored range are missing from the bundle",
                    "entries": "the entries root does not match the chain", "receipts": "the receipts root does not match the chain",
                    "window": "the bundle's window record does not match the chain"}
            run.add("I3", MISMATCH, w, "%s: %s for %s." % (display(w), "; ".join(what[k] for k in kinds), label),
                    code="+".join(kinds), seq=(lo, hi) if not heartbeat else None, tx=a["tx_hash"],
                    evidence=[t for _, t in problems] + ["anchor tx: %s" % a["tx_hash"]])
        else:
            ok_windows += 1
    if not bad_any:
        newest = anchors[-1]
        run.add("I3", MATCH, w, "%s: all %d anchored window(s) match the chain (entries root and receipts root recomputed)." % (
            display(w), ok_windows), code="ok", tx=newest["tx_hash"],
            seq=(anchors[0]["first_seq"], max(a["last_seq"] for a in anchors)) if any(a["last_seq"] >= a["first_seq"] for a in anchors) else None,
            evidence=["windows 1-%d compared; newest anchor tx %s" % (newest["batch_no"], newest["tx_hash"])])
    last_anchored = max((a["last_seq"] for a in anchors), default=0)
    newer = sorted(s for s in b.by_seq if s > last_anchored)
    if newer:
        run.notices.append("%s: %d newest entries (%s) come after the last anchored window and are not on the chain yet" % (
            display(w), len(newer), seq_text(newer[0], newer[-1])))


# ====================================================================== I5
def _ts_ok(x):
    return isinstance(x, str) and bool(TS.match(x))


def rule_i5(run, w):
    b = run.bundle(w)
    if b is None:
        return run.cannot_without_bundle("I5", w, "which entries other witnesses vouched for")
    if run.chain_error:
        return run.chain_unreadable("I5", w, "authenticators")
    key = run.keys.get(w)
    if key is None:
        return run.add("I5", CANNOT, w, "No on-chain key was found for the %s." % display(w), code="no-key")
    peers = run.peers_of(w)
    peer_bundles = [p for p in peers if p in run.bundles]
    if not peer_bundles:
        return run.add("I5", CANNOT, w, "No bundle from any other witness was supplied, so nobody can vouch for the entries of the %s." %
                       display(w), code="no-peers", evidence=["peer bundles supplied: 0 of %d" % len(peers)])

    # authenticators about W held by the other witnesses (signature must verify under W's chain key)
    auths, skipped = {}, 0
    for p in peer_bundles:
        for a in run.bundle(p).authenticators:
            if isinstance(a, dict) and a.get("witness_id") == w and isinstance(a.get("seq"), int):
                if verify_authenticator(key, a):
                    auths.setdefault((a["seq"], a.get("hash")), set()).add(p)
                else:
                    skipped += 1
    deleted, changed, authed = {}, {}, set()
    for (seq, h), holders in auths.items():
        e = b.by_seq.get(seq)
        if e is None:
            deleted[seq] = holders
        elif e.get("hash") != h:
            changed[seq] = (h, holders)
        else:
            authed.add(seq)

    for lo, hi in runs(deleted):
        who = sorted(set().union(*[deleted[s] for s in range(lo, hi + 1) if s in deleted]), key=witness_sort_key)
        run.add("I5", MISMATCH, w, "%s: %s was vouched for by other witnesses but is not in the bundle (deleted)." % (
            display(w), seq_text(lo, hi)), code="deleted", seq=(lo, hi), witnesses=[w] + who,
            evidence=["%s hold(s) a signed authenticator for %s" % (", ".join(display(x) for x in who), seq_text(lo, hi)),
                      "the bundle of the %s has no entry at that seq" % display(w)])
    for lo, hi in runs(changed):
        who = sorted(set().union(*[changed[s][1] for s in range(lo, hi + 1) if s in changed]), key=witness_sort_key)
        run.add("I5", MISMATCH, w, "%s: %s differs from what other witnesses were shown (changed after they authenticated it)." % (
            display(w), seq_text(lo, hi)), code="changed", seq=(lo, hi), witnesses=[w] + who,
            evidence=["%s hold(s) an authenticator with another hash for %s" % (", ".join(display(x) for x in who), seq_text(lo, hi))]
            + ["seq %d: peers hold hash %s, the bundle holds %s" % (s, short(changed[s][0]), short(b.by_seq[s].get("hash")))
               for s in range(lo, min(hi, lo + 2) + 1) if s in changed])

    # coverage: an entry is vouched for if some peer authenticated a hash at the same or a LATER seq
    # and the chain of hashes from this entry up to that one is unbroken
    seqs = sorted(b.by_seq)
    covered, running = set(), False
    for i in range(len(seqs) - 1, -1, -1):
        s = seqs[i]
        if s in authed:
            running = True
        elif running:
            nxt = b.by_seq.get(s + 1)
            running = nxt is not None and nxt.get("prev_hash") == b.by_seq[s].get("hash")
        if running:
            covered.add(s)
    uncovered = [s for s in seqs if s not in covered]

    # which peers were demonstrably reachable after an entry was written? (their signed receipts say so)
    receipts = [r for r in run.valid_receipts().values() if r.get("source") == w and _ts_ok(r.get("received_at"))]
    forged, cannot_tail, cannot_bundle = [], [], []
    explained_upto = max(max(deleted, default=0), max(changed, default=0))     # already reported above
    for s in uncovered:
        if s <= explained_upto:
            continue
        ts = b.by_seq[s].get("ts_utc")
        reach = {r["recipient"] for r in receipts if _ts_ok(ts) and r["received_at"] > ts and r["recipient"] != w}
        if not reach:
            cannot_tail.append(s)
        elif any(p not in run.bundles for p in reach):
            cannot_bundle.append(s)
        else:
            forged.append(s)
    for lo, hi in runs(forged):
        run.add("I5", MISMATCH, w, "%s: %s was never authenticated by any other witness although they kept answering (likely forged)." % (
            display(w), seq_text(lo, hi)), code="likely-forged", seq=(lo, hi), witnesses=[w] + peer_bundles,
            evidence=["no authenticator at or after %s matches this chain" % seq_text(lo, hi),
                      "signed receipts from other witnesses are dated after the entry's time, so they were reachable"])
    for lo, hi in runs(cannot_bundle):
        run.add("I5", CANNOT, w, "%s: %s was not vouched for in the bundles supplied, and a witness that was reachable then sent no bundle." % (
            display(w), seq_text(lo, hi)), code="peer-bundle-missing", seq=(lo, hi),
            evidence=["a witness whose bundle is missing issued receipts after this entry"])
    for lo, hi in runs(cannot_tail):
        run.add("I5", CANNOT, w, "%s: %s has no authenticator from another witness, and no witness is shown to have been reachable after it." % (
            display(w), seq_text(lo, hi)), code="peers-unreachable", seq=(lo, hi),
            evidence=["no signed receipt from another witness is dated after this entry"])
    if skipped:
        run.notices.append("%s: %d authenticator(s) about this witness had a bad signature and were not used (see I2)" % (display(w), skipped))
    if not (deleted or changed or forged or cannot_bundle or cannot_tail):
        who = sorted({p for h in auths.values() for p in h}, key=witness_sort_key)
        run.add("I5", MATCH, w, "%s: all %d entries are vouched for by authenticators held by %s." % (
            display(w), len(seqs), ", ".join(display(x) for x in who) or "other witnesses"), code="ok",
            seq=(seqs[0], seqs[-1]) if seqs else None,
            evidence=["%d authenticators checked from %s" % (len(auths), ", ".join(display(p) for p in peer_bundles))])


# ====================================================================== I6
def rule_i6(run, w):
    b = run.bundle(w)
    if b is None:
        return run.cannot_without_bundle("I6", w, "its receipts")
    if run.chain_error:
        return run.chain_unreadable("I6", w, "receipts")
    anchors = run.anchors.get(w)
    key = run.keys.get(w)
    if anchors is None or key is None:
        return run.add("I6", CANNOT, w, "The anchors or key of the %s could not be read from the chain." % display(w), code="no-chain")
    by_window = {a["batch_no"]: a for a in anchors}
    wins = {x.get("window_no"): x for x in b.windows if isinstance(x, dict)}
    horizon = max((wins[n].get("last_batch") for n in by_window if n in wins and isinstance(wins[n].get("last_batch"), int)), default=0)

    # every receipt this witness signed: its own list, plus the ones other witnesses hold
    mine = {}
    for item in b.receipts_issued:
        r = item.get("receipt") if isinstance(item, dict) else None
        h = receipt_hash_of(r) if isinstance(r, dict) else None
        if h:
            mine[h] = (r, item, "own bundle")
    held = {}
    for pid, pb in run.bundles.items():
        if pid == w:
            continue
        for item in pb.receipts_received:
            r = item.get("receipt") if isinstance(item, dict) else None
            h = receipt_hash_of(r) if isinstance(r, dict) else None
            if h and isinstance(r, dict) and r.get("recipient") == w and verify_receipt(key, r):
                held[h] = (r, item, "held by %s" % display(pid))
    everything = {**held, **mine}

    problems, checked, later, unmapped = {}, 0, 0, []
    root_ok = {}
    for h, (r, item, where) in sorted(everything.items(), key=lambda kv: (kv[1][0].get("recipient_batch") or 0, kv[0])):
        rb = r.get("recipient_batch")
        if not isinstance(rb, int):
            problems.setdefault(None, []).append("a receipt has no recipient_batch (%s)" % where)
            continue
        if rb > horizon:
            later += 1
            continue
        win_no = next((n for n, x in wins.items() if isinstance(x.get("first_batch"), int) and x["first_batch"] <= rb <= x["last_batch"]), None)
        if win_no is None or win_no not in by_window:
            unmapped.append("receipt for %s batch %s (batch %d, %s)" % (r.get("source"), r.get("source_batch"), rb, where))
            continue
        if win_no not in root_ok:
            root, hashes, why = window_receipt_root(run, w, wins[win_no])
            root_ok[win_no] = (root == by_window[win_no]["receipts_root"] and not why, set(hashes))
        reproduces, hashes = root_ok[win_no]
        if h not in hashes:
            # this receipt was signed by the witness, yet it is not among the receipts the bundle lists for the window
            checked += 1
            problems.setdefault(win_no, []).append(
                "receipt for %s batch %s (%s) is not among the receipts the bundle lists for window %d, "
                "so it cannot be in the anchored receiptsRoot" % (r.get("source"), r.get("source_batch"), where, win_no))
            continue
        if not reproduces:
            unmapped.append("window %d: the bundle's receipts do not reproduce the anchored receiptsRoot (see I3)" % win_no)
            continue
        checked += 1
        if where == "own bundle" and item.get("included_in_batch") != rb:
            problems.setdefault(win_no, []).append("receipt for %s batch %s was filed under batch %s but signed as batch %s" % (
                r.get("source"), r.get("source_batch"), item.get("included_in_batch"), rb))

    if later:
        run.notices.append("%s: %d receipt(s) belong to a window that is not anchored yet and were not checked" % (display(w), later))
    for win_no, texts in sorted(problems.items(), key=lambda kv: (kv[0] is None, kv[0])):
        a = by_window.get(win_no)
        run.add("I6", MISMATCH, w, "%s: %d receipt(s) it issued do not appear in its anchored receipts root%s." % (
            display(w), len(texts), " for window %d" % win_no if win_no else ""), code="missing-receipt",
            seq=(a["first_seq"], a["last_seq"]) if a and a["last_seq"] >= a["first_seq"] else None,
            tx=a["tx_hash"] if a else None, evidence=texts[:6])
    if unmapped:
        run.add("I6", CANNOT, w, "%s: %d receipt(s) could not be placed in an anchored window." % (display(w), len(unmapped)),
                code="unplaced", evidence=sorted(set(unmapped))[:6])
    if not problems and not unmapped:
        if checked:
            newest = by_window[max(n for n in by_window if n in wins)]
            run.add("I6", MATCH, w, "%s: all %d receipt(s) it issued appear in the anchored receipts roots." % (display(w), checked),
                    code="ok", tx=newest["tx_hash"],
                    evidence=["%d receipts (own bundle %d, held by other witnesses %d)" % (
                        checked, len(mine), len([h for h in held if h not in mine]))])
        else:
            run.add("I6", CANNOT, w, "%s: no receipt falls inside an anchored window, so nothing could be checked." % display(w),
                    code="nothing-to-check", evidence=["receipts known: %d; not anchored yet: %d" % (len(everything), later)])


# ====================================================================== I7
def rule_i7(run, w):
    key = run.keys.get(w)
    if run.chain_error:
        return run.chain_unreadable("I7", w, "batch headers")
    if key is None:
        return run.add("I7", CANNOT, w, "No on-chain key was found for the %s." % display(w), code="no-key")
    seen = {}      # batch_no -> {canonical bytes: [where, header]}
    examined = 0

    def note(where, header):
        nonlocal examined
        if isinstance(header, dict) and header.get("witness_id") == w and isinstance(header.get("batch_no"), int) \
                and verify_batch_header(key, header):
            examined += 1
            try:
                blob = canonical_json(header)
            except (TypeError, ValueError):
                return
            seen.setdefault(header["batch_no"], {}).setdefault(blob, [header, []])[1].append(where)

    for pid, pb in run.bundles.items():
        if pid == w:
            for item in pb.batches:
                note("its own batches list", item.get("header") if isinstance(item, dict) else None)
        for item in pb.peer_headers:
            if isinstance(item, dict) and item.get("from_witness") == w:
                note("held by %s" % display(pid), item.get("header"))
        for item in pb.conflicting_headers:
            if isinstance(item, dict) and item.get("from_witness") == w:
                note("held by %s as a conflicting header" % display(pid), item.get("header"))
    clashes = {n: v for n, v in seen.items() if len(v) > 1}
    for n, versions in sorted(clashes.items()):
        ev = ["version %d: entries_root %s, signature %s... (%s)" % (
            i + 1, short(h["entries_root"]), str(h["sig"])[:10], brief(sorted(set(wh)), 3))
            for i, (h, wh) in enumerate(versions.values())]
        run.add("I7", MISMATCH, w, "%s: it signed %d different headers for batch %d." % (display(w), len(versions), n),
                code="two-headers", witnesses=[w] + sorted([p for p in run.bundles if p != w], key=witness_sort_key),
                evidence=ev)
    if clashes:
        return
    if w in run.bundles and examined:
        run.add("I7", MATCH, w, "%s: no batch number has two different signed headers (%d headers examined)." % (display(w), examined),
                code="ok", evidence=["%d signed headers across %d bundle(s)" % (examined, len(run.bundles))])
    else:
        run.add("I7", CANNOT, w, "Not enough evidence about the headers of the %s." % display(w), code="no-evidence",
                evidence=["headers examined: %d; its own bundle supplied: %s" % (examined, "yes" if w in run.bundles else "no")])


RULE_FUNCTIONS = (("I1", rule_i1), ("I2", rule_i2), ("I3", rule_i3), ("I4", rule_i4),
                  ("I5", rule_i5), ("I6", rule_i6), ("I7", rule_i7))


# ============================================================== the whole run
class Report:
    def __init__(self, run, bundle_notes):
        self.run = run
        self.findings = run.findings
        self.notices = run.notices
        self.bundle_notes = bundle_notes

    @property
    def chain_error(self):
        return self.run.chain_error

    @property
    def overall(self):
        results = {f.result for f in self.findings}
        return worst(results) if results else CANNOT

    @property
    def exit_code(self):
        return {MATCH: 0, MISMATCH: 1, CANNOT: 2}[self.overall]

    def matrix(self):
        rows = {}
        for rule in RULES:
            rows[rule] = {w: worst({f.result for f in self.findings if f.rule == rule and f.subject == w} or {CANNOT})
                          for w in self.run.subjects()}
        return rows

    def find(self, finding_id):
        return next((f for f in self.findings if f.id == finding_id.upper()), None)


def verify(bundle_paths, reader):
    """Run every rule. `bundle_paths` are files; `reader` is a chain reader. Never touches a live witness."""
    bundles, notes = {}, []
    for path in bundle_paths:
        try:
            b = load_bundle(path)
        except BundleError as err:
            notes.append((str(path), "unreadable: %s" % err))
            continue
        if b.witness_id in bundles:
            notes.append((str(path), "ignored: a bundle for '%s' was already supplied (%s)" % (b.witness_id, bundles[b.witness_id].path)))
            continue
        bundles[b.witness_id] = b

    run = Run(bundles, reader)
    run.load_chain()

    # input problems are findings too: never silently dropped
    for path, why in notes:
        run.findings.append(Finding(rule="I1", result=CANNOT, subject="", statement="A bundle file was not used: %s." % why,
                                    code="input", witnesses=[], evidence=["file: %s" % path],
                                    limitation="Missing evidence is never counted as a match.",
                                    answerable_by="whoever supplied the file"))
    if run.chain_error:
        run.notices.append("The chain could not be read: %s" % run.chain_error)
    else:
        for wid in sorted(bundles, key=witness_sort_key):
            if wid not in run.registered:
                run.findings.append(Finding(
                    rule="I2", result=CANNOT, subject=wid, witnesses=[wid], code="unregistered",
                    statement="A bundle claims to come from '%s', which is not registered on the chain, so no key can check it." % wid,
                    evidence=["registered on the chain: %s" % ", ".join(run.registered)],
                    limitation="Keys come only from the chain.", answerable_by="whoever supplied the bundle"))
    if not run.subjects():
        run.findings.append(Finding(rule="I1", result=CANNOT, subject="", statement="Nothing was supplied that can be checked.",
                                    code="empty", witnesses=[], limitation="Missing evidence is never counted as a match.",
                                    answerable_by="whoever ran the verifier"))
    for w in run.subjects():
        for _rule, fn in RULE_FUNCTIONS:
            fn(run, w)

    run.findings.sort(key=lambda f: f.sort_key())
    for i, f in enumerate(run.findings, start=1):
        f.id = "F-%04d" % i
    run.notices[:] = sorted(set(run.notices), key=run.notices.index)
    return Report(run, notes)
