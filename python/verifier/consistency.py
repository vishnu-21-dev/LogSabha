"""The consistency rules C1 to C4 and C6.

They compare what the witnesses wrote about the same traffic, using the numbers in the policy file
(threshold, time window, byte tolerance). Two promises from the integrity rules still hold:
  - missing evidence is never MATCH;
  - silence (a witness that has no signed batches over a time, or no bundle) is CANNOT VERIFY, never MISMATCH.
A witness "covers" a time when it holds signed batch headers (heartbeats are empty batches) over it.
A record that has no partner is a MISMATCH only when the other witness covers that time.

C6 is different: it only prints WARNINGS. They never change the verdict or the exit code.
"""
from datetime import datetime, timezone

from logsabha_core import verify_batch_header
from logsabha_core.policy import PolicyError, normalize_destination

from .model import CANNOT, MATCH, MISMATCH, WARNING, Finding, display
from .rules import brief, seq_text, short

COVER_GAP = 6.0       # seconds: consecutive signed batches closer than this count as continuous cover
LEAD = 2.5            # seconds a first batch covers before its own time (about one batch interval)

LIMITS = {
    "C1": "Matches records by request id, direction, destination, time and byte count. Times are the moments each witness "
          "wrote its record (not the moment the traffic happened), and a delayed post can move a record outside the time window. "
          "Cover is judged from the witness's own batch times, which are not signed.",
    "C2": "Same matching as C1, in the other direction. An App call that ended in a timeout may be written by the Network "
          "witness later than the time window. A call that never reached the gateway is listed as a notice, not checked.",
    "C3": "Joins by destination and time only (the Outside witness may not see request ids). Packet capture can count a few "
          "extra header bytes on small flows, so small flows can differ by more than the tolerance. Destinations the Outside "
          "witness never watches are listed as notices. The shared-input check is a heuristic: it looks for identical "
          "millisecond times and byte counts on every compared flow, which two independent witnesses almost never produce.",
    "C4": "Reads block times from the chain. Time spent inside an approved planned pause is not counted as silence. "
          "A silence finding says the witness was quiet; it does not say why.",
    "C6": "A warning is a prompt to look, not a verdict. It never changes the result or the exit code.",
}


# ---------------------------------------------------------------- small helpers
def parse_ts(text):
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def within_tolerance(a, b, percent):
    return abs(a - b) * 100 <= percent * max(a, b)


def records(run, role, event_type, direction):
    """The entries of one witness with this event type and direction, as plain dicts."""
    b = run.bundle(run.role_id(role))
    out = []
    if b is None:
        return out
    for e in b.entries:
        if not isinstance(e, dict) or e.get("event_type") != event_type or e.get("direction") != direction:
            continue
        t, n, seq = parse_ts(e.get("ts_utc")), e.get("bytes"), e.get("seq")
        if t is None or isinstance(n, bool) or not isinstance(n, int) or isinstance(seq, bool) or not isinstance(seq, int):
            continue
        try:
            dst = normalize_destination(e.get("dst"))
        except (PolicyError, AttributeError):
            continue
        out.append({"seq": seq, "t": t, "ts": e["ts_utc"], "dst": dst, "bytes": n, "rid": str(e.get("request_id") or ""),
                    "result": str(e.get("result") or ""), "role": role})
    return sorted(out, key=lambda r: r["seq"])


def label(r):
    rid = ("request " + r["rid"][:8]) if r["rid"] else "no request id"
    return "%s seq %d at %s to %s, %d bytes, %s" % (display(r["role"]), r["seq"], r["ts"], r["dst"], r["bytes"], rid)


def coverage(run, w):
    """[(from, to)] epoch seconds in which witness w holds correctly signed batch headers (its own bundle)."""
    if w in run._coverage:
        return run._coverage[w]
    b, key, times = run.bundle(w), run.keys.get(w), []
    if b is not None and key is not None:
        for item in b.batches:
            h, t = (item.get("header"), item.get("created_at")) if isinstance(item, dict) else (None, None)
            if not isinstance(h, dict) or isinstance(t, bool) or not isinstance(t, (int, float)):
                continue
            try:
                ok = verify_batch_header(key, h)
            except Exception:
                ok = False
            if ok:
                times.append(float(t))
    times.sort()
    spans = []
    for i, t in enumerate(times):
        lo = times[i - 1] if i and t - times[i - 1] <= COVER_GAP else t - LEAD
        if spans and lo <= spans[-1][1] + 1e-9:
            spans[-1] = (spans[-1][0], t)
        else:
            spans.append((lo, t))
    run._coverage[w] = spans
    return spans


def covers(run, role, t):
    return any(lo <= t <= hi for lo, hi in coverage(run, run.role_id(role)))


def tx_for(run, w, seq):
    b = run.bundle(w)
    if b is None:
        return None
    for win in b.windows:
        if isinstance(win, dict) and isinstance(win.get("first_seq"), int) and isinstance(win.get("last_seq"), int) \
                and win["first_seq"] <= seq <= win["last_seq"]:
            return win.get("tx_hash")
    return None


def span_text(rs):
    return "%s to %s" % (min(r["ts"] for r in rs), max(r["ts"] for r in rs)) if rs else "n/a"


def policy_gate(run, rule, subject):
    """If the policy cannot be trusted, this rule cannot be checked. Returns True when it was stopped here."""
    if run.policy_state == "ok":
        return False
    run.add(rule, CANNOT, subject,
            "This rule reads values from the policy (threshold, time window, tolerance), but the policy in force cannot be "
            "confirmed, so it cannot be checked.",
            code="policy", evidence=["policy: %s" % run.policy_note,
                                     "policy supplied: %s" % run.policy_label],
            limitation="The policy hash is anchored on the chain with every window. A policy file that does not match "
                       "it is not trusted, and every rule that reads a policy value stops.",
            witnesses=[subject])
    return True


def need_bundles(run, rule, subject, roles, what):
    missing = [r for r in roles if run.bundle(run.role_id(r)) is None]
    if missing:
        run.add(rule, CANNOT, subject, "No evidence bundle was supplied for the %s, so %s cannot be checked." % (
            " and the ".join(display(run.role_id(r)) for r in missing), what), code="no-bundle",
            evidence=["missing bundle(s): %s" % ", ".join(missing)],
            limitation="Missing evidence is never counted as a match. Supply the bundle to check this rule.",
            witnesses=[run.role_id(r) for r in roles])
        return True
    return False


def warn(run, subject, statement, code, evidence, seq=None, time_range="n/a"):
    run.warnings.append(Finding(
        rule="C6", result=WARNING, subject=subject, statement=statement, code=code, witnesses=[subject],
        seq_range=seq, time_range=time_range, evidence=list(evidence), limitation=LIMITS["C6"],
        anchor_tx=tx_for(run, subject, seq[0]) if seq else None, answerable_by=display(subject) + " operator"))


# ------------------------------------------------------------------ matching
def index_by_rid(pool):
    out = {}
    for r in pool:
        out.setdefault(r["rid"], []).append(r)
    return out


def find_partner(rec, by_rid, used, window, tolerance):
    """The closest unused record with the same request id, destination and size, within the time window."""
    if not rec["rid"]:
        return None
    best = None
    for c in by_rid.get(rec["rid"], []):
        if id(c) in used or c["dst"] != rec["dst"]:
            continue
        dt = abs(c["t"] - rec["t"])
        if dt <= window and within_tolerance(rec["bytes"], c["bytes"], tolerance) and (best is None or dt < best[0]):
            best = (dt, c)
    return best[1] if best else None


def near_miss(rec, pool_by_rid, other_role):
    same = pool_by_rid.get(rec["rid"], []) if rec["rid"] else []
    if not same:
        return "%s holds no record with this request id" % display(other_role) if rec["rid"] else \
               "this record has no visible request id, so nothing can be matched to it"
    c = same[0]
    return "closest %s record with this request id: %s" % (display(other_role), label(c))


def one_direction(run, rule, subject, from_role, to_role, source, pool, extra_evidence, what_matched, skip=None):
    """Shared by C1 and C2: every record in `source` needs a partner in `pool` (written by `to_role`)."""
    pol = run.policy
    window, tol = pol["time_window_seconds"], pol["byte_tolerance_percent"]
    by_rid, used, matched, problems = index_by_rid(pool), set(), [], 0
    for rec in source:
        if skip and skip(rec):
            run.notices.append("%s seq %d was not checked: %s" % (display(from_role), rec["seq"], skip(rec)))
            continue
        partner = find_partner(rec, by_rid, used, window, tol)
        if partner is not None:
            used.add(id(partner))
            matched.append(rec)
            continue
        problems += 1
        ev = [label(rec), near_miss(rec, by_rid, to_role),
              "rule: same request id, direction, destination, within %d s and %d %% of the bytes (policy %s)" % (
                  window, tol, pol["version"])] + extra_evidence
        expected = display(run.role_id(to_role)) + " operator"           # the witness that should hold the record explains it
        if covers(run, to_role, rec["t"]):
            f = run.add(rule, MISMATCH, subject,
                    "%s has no matching record: %s." % (display(to_role), label(rec)), code="no-partner",
                    seq=(rec["seq"], rec["seq"]), evidence=ev + ["%s holds signed batches over this time" % display(to_role)],
                    tx=tx_for(run, subject, rec["seq"]) if from_role == run.role_id(subject) else None,
                    limitation=LIMITS[rule], witnesses=[run.role_id("network"), run.role_id("app")])
            f.answerable_by = expected
        else:
            f = run.add(rule, CANNOT, subject,
                    "%s has no signed batches over this time, so it cannot be said whether it saw: %s." % (display(to_role), label(rec)),
                    code="no-cover", seq=(rec["seq"], rec["seq"]),
                    evidence=ev + ["%s holds no signed batch over %s" % (display(to_role), rec["ts"])],
                    limitation=LIMITS[rule], witnesses=[run.role_id("network"), run.role_id("app")])
            f.answerable_by = expected
    if matched:
        run.add(rule, MATCH, subject,
                "%d of %d record(s) checked %s." % (len(matched), len(matched) + problems, what_matched),
                code="ok", evidence=["policy %s: window %d s, tolerance %d %%" % (pol["version"], window, tol)] +
                [label(r) for r in matched[:3]] + (["and %d more" % (len(matched) - 3)] if len(matched) > 3 else []),
                limitation=LIMITS[rule], time_range=span_text(matched), witnesses=[run.role_id("network"), run.role_id("app")])
    elif not problems:
        run.add(rule, MATCH, subject, "There was nothing to compare: no record needed a partner (%s)." % extra_evidence[0],
                code="vacuous", evidence=extra_evidence + ["policy %s" % pol["version"]], limitation=LIMITS[rule],
                witnesses=[run.role_id("network"), run.role_id("app")])


# ====================================================================== C1
def rule_c1(run):
    net = run.role_id("network")
    if policy_gate(run, "C1", net) or need_bundles(run, "C1", net, ("network", "app"), "network to app matching"):
        return
    threshold = run.policy["egress_threshold_bytes"]
    big = [r for r in records(run, "network", "connection", "out") if r["bytes"] >= threshold]
    app_out = records(run, "app", "outbound_call", "out")
    one_direction(run, "C1", net, "network", "app", big, app_out,
                  ["egress threshold: %d bytes; %d Network record(s) reached it" % (threshold, len(big))],
                  "reached the threshold of %d bytes and were each matched by an App witness event" % threshold)


# ====================================================================== C2
def rule_c2(run):
    app = run.role_id("app")
    if policy_gate(run, "C2", app) or need_bundles(run, "C2", app, ("app", "network"), "app to network matching"):
        return
    app_out = records(run, "app", "outbound_call", "out")
    net = records(run, "network", "connection", "out")

    def skip(rec):
        return "the call ended in error:gateway_unreachable, so it never reached the Network witness's gateway" \
            if rec["result"] == "error:gateway_unreachable" else None

    one_direction(run, "C2", app, "app", "network", app_out, net,
                  ["%d App outbound event(s) examined" % len(app_out)],
                  "of the App witness's outbound events were each matched by a Network witness event", skip=skip)


# ====================================================================== C3
def rule_c3(run):
    out_id, net_id = run.role_id("outside"), run.role_id("network")
    if policy_gate(run, "C3", out_id) or need_bundles(run, "C3", out_id, ("outside", "network"), "the Outside witness comparison"):
        return
    window, tol, ver = run.policy["time_window_seconds"], run.policy["byte_tolerance_percent"], run.policy["version"]
    flows = records(run, "outside", "flow", "in")
    conns = records(run, "network", "connection", "out")
    if not flows:
        run.add("C3", CANNOT, out_id, "The Outside witness holds no flow records, so there is nothing to compare with the Network witness.",
                code="no-records", evidence=["Outside witness flow records: 0"], limitation=LIMITS["C3"], witnesses=[out_id, net_id])
        return
    # pair each Outside flow with the closest unused Network record for the same destination in time
    pairs, used, unpaired = [], set(), []
    for f in flows:
        best = None
        for c in conns:
            if id(c) not in used and c["dst"] == f["dst"] and abs(c["t"] - f["t"]) <= window:
                if best is None or abs(c["t"] - f["t"]) < best[0]:
                    best = (abs(c["t"] - f["t"]), c)
        if best:
            used.add(id(best[1]))
            pairs.append((f, best[1]))
        else:
            unpaired.append(f)
    # shared input: identical millisecond times and byte counts on every compared flow
    if len(pairs) >= 2 and all(f["ts"] == c["ts"] and f["bytes"] == c["bytes"] for f, c in pairs):
        run.add("C3", CANNOT, out_id,
                "Shared input: the Outside witness's records equal the Network witness's records on every compared flow, to the millisecond. "
                "Two independent witnesses would not do that, so this is not independent evidence.",
                code="shared-input", seq=(min(f["seq"] for f, _ in pairs), max(f["seq"] for f, _ in pairs)),
                evidence=["%d flow(s) compared; every one has the same time (to the millisecond) and the same byte count in both witnesses" % len(pairs),
                          "example: %s  |  %s" % (label(pairs[0][0]), label(pairs[0][1]))],
                limitation=LIMITS["C3"], witnesses=[out_id, net_id])
        return
    seen_dsts = sorted({f["dst"] for f in flows})
    for dst in seen_dsts:
        fs = [f for f in flows if f["dst"] == dst]
        cs = [c for c in conns if c["dst"] == dst]
        blind = [f for f in fs if not covers(run, "network", f["t"])] + [c for c in cs if not covers(run, "outside", c["t"])]
        o_sum, n_sum = sum(f["bytes"] for f in fs), sum(c["bytes"] for c in cs)
        ev = ["destination %s" % dst, "Outside witness: %d flow(s), %d bytes" % (len(fs), o_sum),
              "Network witness: %d connection(s), %d bytes" % (len(cs), n_sum),
              "rule: totals within %d %% (policy %s)" % (tol, ver)]
        lonely = [f for f in unpaired if f["dst"] == dst]
        if blind:
            run.add("C3", CANNOT, out_id, "For %s the two witnesses did not both hold signed batches over every record, so the totals cannot be compared." % dst,
                    code="no-cover", seq=(min(f["seq"] for f in fs), max(f["seq"] for f in fs)),
                    evidence=ev + ["no cover over: " + brief(label(r) for r in blind[:3])], limitation=LIMITS["C3"], witnesses=[out_id, net_id])
        elif not within_tolerance(o_sum, n_sum, tol) or lonely:
            why = "the totals differ by more than %d %%" % tol if not within_tolerance(o_sum, n_sum, tol) else \
                "an Outside record has no Network record within %d s" % window
            run.add("C3", MISMATCH, out_id, "For %s the Outside witness and the Network witness disagree: %s." % (dst, why),
                    code="totals", seq=(min(f["seq"] for f in fs), max(f["seq"] for f in fs)),
                    evidence=ev + [label(f) for f in lonely[:3]],
                    tx=tx_for(run, out_id, fs[0]["seq"]), limitation=LIMITS["C3"], witnesses=[out_id, net_id])
        else:
            run.add("C3", MATCH, out_id, "For %s the Outside witness and the Network witness agree (%d vs %d bytes)." % (dst, o_sum, n_sum),
                    code="ok", seq=(min(f["seq"] for f in fs), max(f["seq"] for f in fs)), evidence=ev,
                    tx=tx_for(run, out_id, fs[0]["seq"]), limitation=LIMITS["C3"], witnesses=[out_id, net_id])
    unseen = sorted({c["dst"] for c in conns} - set(seen_dsts))
    if unseen:
        run.notices.append("C3: the Outside witness never observed %s, so these destinations were not compared." % ", ".join(unseen))


# ====================================================================== C4
def subtract(lo, hi, cuts):
    """The pieces of [lo, hi] that are not inside any (a, b) in cuts."""
    pieces = [(lo, hi)]
    for a, b in cuts:
        nxt = []
        for p, q in pieces:
            if b <= p or a >= q:
                nxt.append((p, q))
                continue
            if a > p:
                nxt.append((p, a))
            if b < q:
                nxt.append((b, q))
        pieces = nxt
    return pieces


def pauses_of(events, w):
    ended = {e["pause_id"]: e["block_time"] for e in events if e["type"] == "PauseEnded" and e["witness"] == w}
    out = []
    for e in events:
        if e["type"] == "PauseBegun" and e["witness"] == w:
            end = min(e["pause_until"], ended.get(e["pause_id"], e["pause_until"]))
            out.append({"start": e["start"], "end": end, "tx": e.get("tx_hash"), "id": e["pause_id"]})
    return out


def rule_c4(run):
    for w in run.subjects():
        if run.chain_error:
            run.chain_unreadable("C4", w, "silence and missed anchors")
    if run.chain_error:
        return
    events = run.events["events"] if run.events else []
    if run.events is None:
        run.notices.append("C4: chain events could not be read (%s), so silence flags and planned pauses were not considered." % run.events_error)
    horizon = max((a["block_time"] for w in run.registered for a in (run.anchors.get(w) or []) if a.get("block_time")), default=None)
    for w in run.registered:
        anchors = run.anchors.get(w)
        info = run.chain_info.get(w, {})
        max_gap = int(info.get("max_gap_seconds") or 0)
        if anchors is None:
            run.add("C4", CANNOT, w, "The anchors of the %s could not be read from the chain." % display(w), code="no-anchors-read",
                    evidence=["chain: %s" % run.anchor_error.get(w, "unknown")], limitation=LIMITS["C4"])
            continue
        times = sorted(a["block_time"] for a in anchors if a.get("block_time"))
        flags = [e for e in events if e["type"] == "WitnessSilent" and e["witness"] == w]
        pauses = pauses_of(events, w)
        for p in pauses:
            run.notices.append("C4: planned pause for the %s from %s to %s (approved on the chain, tx %s). Time inside it is not counted as silence."
                               % (display(w), iso(p["start"]), iso(p["end"]), short(p["tx"] or "unknown")))
        if not times:
            run.add("C4", CANNOT, w, "The chain holds no anchors from the %s%s." % (
                display(w), "" if horizon is None else " although other witnesses have anchored"),
                code="no-anchors", evidence=["anchors on the chain for this witness: 0"], limitation=LIMITS["C4"])
        elif max_gap <= 0:
            run.add("C4", CANNOT, w, "The chain gives no allowed silence limit (maxGapSeconds) for the %s." % display(w),
                    code="no-limit", evidence=["maxGapSeconds: %s" % info.get("max_gap_seconds")], limitation=LIMITS["C4"])
        else:
            points = times + ([horizon] if horizon and horizon > times[-1] else [])
            gaps = []
            for a, b in zip(points, points[1:]):
                if b - a > max_gap:
                    gaps += [(lo, hi) for lo, hi in subtract(a, b, [(p["start"], p["end"]) for p in pauses]) if hi - lo > max_gap]
            tx_of = {a["block_time"]: a.get("tx_hash") for a in anchors}
            for lo, hi in gaps:
                run.add("C4", CANNOT, w, "Silence: no anchor or heartbeat from the %s between %s and %s (%d s; the chain allows %d s)." % (
                    display(w), iso(lo), iso(hi), hi - lo, max_gap), code="gap", time_range="%s to %s" % (iso(lo), iso(hi)),
                    evidence=["allowed gap on the chain (maxGapSeconds): %d" % max_gap, "gap: %d s" % (hi - lo),
                              "anchor before the gap: tx %s" % short(tx_of.get(lo) or "unknown")],
                    tx=tx_of.get(lo), limitation=LIMITS["C4"])
            if not gaps and not flags:
                longest = max((b - a for a, b in zip(points, points[1:])), default=0)
                run.add("C4", MATCH, w, "No silence from the %s: %d anchor(s), longest quiet stretch %d s (allowed %d s)%s." % (
                    display(w), len(times), longest, max_gap, "; planned pause(s) not counted" if pauses else ""),
                    code="ok", time_range="%s to %s" % (iso(times[0]), iso(points[-1])),
                    evidence=["anchors: %d" % len(times), "allowed gap (maxGapSeconds): %d" % max_gap], limitation=LIMITS["C4"])
        for e in flags:
            run.add("C4", CANNOT, w, "The chain records that the %s was flagged silent at %s." % (display(w), iso(e["flagged_at"])),
                    code="silent-event", time_range="last seen %s, flagged %s" % (iso(e["last_seen"]), iso(e["flagged_at"])),
                    evidence=["WitnessSilent event read from the chain (tx %s)" % short(e.get("tx_hash") or "unknown"),
                              "last seen by the chain: %s" % iso(e["last_seen"]), "flagged at: %s" % iso(e["flagged_at"])],
                    tx=e.get("tx_hash"), limitation=LIMITS["C4"])
        b = run.bundle(w)
        if b is not None and times:
            last_no = max(a["batch_no"] for a in anchors)
            tail = [x for x in b.windows if isinstance(x, dict) and isinstance(x.get("window_no"), int) and x["window_no"] > last_no]
            if tail:
                run.notices.append("C4: the %s has %d newest window(s) not anchored yet (for example the last one, made when it stopped)." % (display(w), len(tail)))


# ====================================================================== C6
def rule_c6(run):
    net = run.role_id("network")
    if run.policy_state != "ok":
        run.notices.append("C6 was not run: the policy in force cannot be confirmed (%s)." % run.policy_note)
        return
    if run.bundle(net) is None:
        run.notices.append("C6 was not run: no Network witness bundle was supplied.")
        return
    pol = run.policy
    conns = records(run, "network", "connection", "out")
    normal = set(pol["normal_destinations"])
    for dst in sorted({c["dst"] for c in conns} - normal):
        rs = [c for c in conns if c["dst"] == dst]
        warn(run, net, "Warning: traffic went to %s, which is not in the policy's list of normal destinations (%d record(s), %d bytes)."
             % (dst, len(rs), sum(r["bytes"] for r in rs)), "new-destination",
             ["destination %s is not in policy %s" % (dst, pol["version"]), label(rs[0])],
             seq=(rs[0]["seq"], rs[-1]["seq"]), time_range=span_text(rs))
    span, limit = pol["cumulative_window_seconds"], pol["cumulative_threshold_bytes"]
    best, j, total = (0, 0, 0), 0, 0
    for i, c in enumerate(conns):
        total += c["bytes"]
        while c["t"] - conns[j]["t"] > span:
            total -= conns[j]["bytes"]
            j += 1
        if total > best[0]:
            best = (total, j, i)
    if best[0] > limit:
        window = conns[best[1]:best[2] + 1]
        warn(run, net, "Warning: %d bytes left in one %d-second window, above the policy's %d." % (best[0], span, limit),
             "cumulative", ["window %s; %d connection(s)" % (span_text(window), len(window)),
                            "threshold: %d bytes in %d seconds (policy %s)" % (limit, span, pol["version"])],
             seq=(window[0]["seq"], window[-1]["seq"]), time_range=span_text(window))


CONSISTENCY_FUNCTIONS = (("C1", rule_c1), ("C2", rule_c2), ("C3", rule_c3), ("C4", rule_c4), ("C6", rule_c6))
