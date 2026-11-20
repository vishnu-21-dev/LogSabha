"""Step G2: consistency rules C1 to C4 and C6, the policy file, and the flush that fixes the tail.

One REAL stack (app, gateway, outside sink, three witnesses, local Hardhat chain) runs once for the whole file:
a clean run, a clean stop, an export, then the verifier. The A-cases edit COPIES of those bundles.
The bundle edits are not re-signed: the C rules read the records, and the integrity rules (I1, I2) would
catch an unsigned edit. The A-cases therefore run the consistency rules only.
Everything is "simulated separation": one laptop, separate ports. No keys are printed; the witness keys are
throw-away files made by the launcher in a temporary folder.
"""
import copy
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests

import clean_run
from launcher import Stack
from logsabha_core.policy import load_policy_file, write_policy_file
from verifier.__main__ import main as verifier_main
from verifier.chain import HelperChainReader, StaticChainReader
from verifier.consistency import iso, parse_ts
from verifier.report import human_report
from verifier.rules import verify
from witness.export import write_bundle

from test_chain_e2e import HELPER, chain_env, helper, node_port        # noqa: F401  (node_port is a fixture)
from test_witness_processes import free_port

FAKE_PASSWORD = "quickpay-test-fake-password"
BIG = 2_000_000                       # the large export that C1 will check
THRESHOLD = 1_000_000                 # above the clean exports (150 kB, 400 kB) and below BIG
EMPTY = "0x" + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def http():
    s = requests.Session()
    s.trust_env = False
    return s


def wait_for(predicate, timeout=60, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.4)
    raise AssertionError("timed out waiting for " + what)


def db_count(path, event_type):
    con = sqlite3.connect(str(path), timeout=10)
    try:
        return sum(1 for (j,) in con.execute("SELECT entry_json FROM entries") if json.loads(j)["event_type"] == event_type)
    finally:
        con.close()


def max_seq(path):
    con = sqlite3.connect(str(path), timeout=10)
    try:
        return con.execute("SELECT COALESCE(MAX(seq),0) FROM entries").fetchone()[0]
    finally:
        con.close()


# ============================================================ the one real stack
@pytest.fixture(scope="module")
def real(node_port, tmp_path_factory):
    data = tmp_path_factory.mktemp("g2stack")
    dep = data / "deployment.json"
    env = chain_env(node_port, dep)
    config = {
        "label": "SIMULATED SEPARATION (test): one laptop, separate ports",
        "data_dir": str(data),
        "batch_interval_seconds": 2,
        "anchor": {"backend": "chain", "interval_seconds": 3, "receipt_grace_seconds": 2, "confirmations": 1,
                   "deployment_file": str(dep)},
        "witnesses": {n: {"host": "127.0.0.1", "port": free_port()} for n in ("app", "network", "outside")},
        "app": {"host": "127.0.0.1", "port": free_port(), "demo_password": FAKE_PASSWORD, "customers": 60},
        "gateway": {"host": "127.0.0.1", "port": free_port()},
        "outside": {"mode": "sink", "host": "127.0.0.1", "port": free_port()},
    }
    stack = Stack(config)
    sink = urlsplit(stack.outside_url).netloc
    policy_path = data / "policy.json"
    write_policy_file(policy_path, {"version": "demo-1", "normal_destinations": [sink],
                                    "egress_threshold_bytes": THRESHOLD})           # time window 5 s, tolerance 5 % = defaults
    config["policy_file"] = str(policy_path)

    # the chain must know the witnesses' PUBLIC keys before the witnesses start
    for d in (stack.keys_dir, stack.logs_dir, stack.run_dir, stack.db_dir):
        d.mkdir(parents=True, exist_ok=True)
    stack._prepare_keys()
    out = helper(env, "setup-local", {"witnesses": stack.public_keys, "maxGapSeconds": 600})
    assert out["ok"], out

    saved = {k: os.environ.get(k) for k in env if k in ("NETWORK", "LOCAL_RPC_URL", "LOCAL_CHAIN_ID", "CHAIN_DEPLOYMENT_FILE")}
    os.environ.update({k: env[k] for k in saved})
    try:
        stack.start(timeout=90)
        steps = clean_run.run(stack.app_url, "analyst", FAKE_PASSWORD, export_url="http://%s/partner-report" % sink,
                              backup_url="http://%s/nightly-backup" % sink)
        login = http().post(stack.app_url + "/login", json={"username": "analyst", "password": FAKE_PASSWORD}, timeout=10)
        r = http().post(stack.app_url + "/export", json={"destination_url": "http://%s/big-export" % sink, "bytes": BIG,
                                                         "purpose": "partner-report"},
                        headers={"Authorization": "Bearer " + login.json()["token"]}, timeout=120)
        assert r.status_code == 200
        big_request_id = r.headers["X-Request-ID"]
        for name, etype, n in (("app", "outbound_call", 3), ("network", "connection", 3), ("outside", "flow", 3)):
            wait_for(lambda: db_count(stack.db_path(name), etype) >= n, what="%s records in the %s witness" % (etype, name))
        # wait until the chain holds an anchor that covers everything written so far
        reader = HelperChainReader(HELPER, deployment_file=dep, env=env)
        target = {n: max_seq(stack.db_path(n)) for n in ("app", "network", "outside")}
        wait_for(lambda: all(reader.witness_keys()[n]["last_seq"] >= target[n] for n in target), timeout=120,
                 what="the chain to anchor the newest entries")
        outcome = stack.stop()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        stack.stop() if stack.procs else None

    bundles_dir = data / "bundles"
    bundles_dir.mkdir()
    paths = stack.export_bundles(bundles_dir)
    yield {"stack": stack, "env": env, "dep": dep, "reader": reader, "paths": paths, "policy": policy_path, "sink": sink,
           "outcome": outcome, "big_request_id": big_request_id, "data": data, "steps": steps}


def static_reader(real):
    return StaticChainReader.from_reader(real["reader"])


@pytest.fixture(scope="module")
def chain_copy(real):
    return static_reader(real)           # chain facts read once; the A-cases then run fast


def load(real, name):
    return json.loads(Path(real["paths"][name]).read_text(encoding="utf-8"))


def write_set(tmp, bundles):
    out = []
    for name, data in bundles.items():
        p = Path(tmp) / (name + ".bundle.json")
        p.write_text(json.dumps(data), encoding="utf-8")
        out.append(str(p))
    return out


def edited(real, tmp_path, **changes):
    """Copies of the three bundles. Each change is a function that edits one bundle (a dict) in place."""
    b = {n: load(real, n) for n in ("app", "network", "outside")}
    for name, fn in changes.items():
        fn(b[name])
    return write_set(tmp_path, b)


def check(real, chain, paths, rules="consistency", policy=None):
    return verify(paths, chain, policy_path=str(policy or real["policy"]), rules=rules)


def by_rule(report, rule, result=None):
    return [f for f in report.findings if f.rule == rule and (result is None or f.result == result)]


def entries_of(bundle, event_type):
    return [e for e in bundle["entries"] if e["event_type"] == event_type]


# =================================================================== 0. the tail fix
def test_the_real_stack_stopped_cleanly_and_each_witness_has_one_shutdown_marker_last(real):
    assert set(real["outcome"].values()) == {"clean"}, real["outcome"]
    for name in ("app", "network", "outside"):
        entries = load(real, name)["entries"]
        assert entries[-1]["event_type"] == "shutdown"
        assert sum(1 for e in entries if e["event_type"] == "shutdown") == 1, name       # stop() did not write a second one


def test_clean_run_after_stop_and_export_is_all_match_with_no_warnings_exit_0(real, chain_copy):
    paths = [str(p) for p in real["paths"].values()]
    report = verify(paths, real["reader"], policy_path=str(real["policy"]), rules="all")        # the real chain, nothing replayed
    bad = [f for f in report.findings if f.result != "MATCH"]
    assert not bad, "\n".join("%s %s %s" % (f.rule, f.result, f.statement) for f in bad)
    assert report.overall == "MATCH" and report.exit_code == 0
    assert report.warnings == []
    # the rules really did check something
    c1 = by_rule(report, "C1", "MATCH")
    assert c1 and "1 of 1" in c1[0].statement and str(THRESHOLD) in c1[0].statement
    assert by_rule(report, "C2", "MATCH") and by_rule(report, "C3", "MATCH") and len(by_rule(report, "C4", "MATCH")) == 3
    assert verifier_main(["verify", "--bundles", *paths, "--policy-file", str(real["policy"]), "--chain-helper", HELPER,
                          "--deployment-file", str(real["dep"])], reader=real["reader"]) == 0


# ======================================================================= policy file
def test_policy_values_are_parameters_and_the_demo_numbers_are_only_defaults(real):
    policy, digest = load_policy_file(real["policy"])
    assert policy["time_window_seconds"] == 5 and policy["byte_tolerance_percent"] == 5          # defaults
    assert policy["egress_threshold_bytes"] == THRESHOLD != 10_000_000                           # set below the demo attack transfer
    assert 400_000 < THRESHOLD < BIG                                                              # above normal traffic, below the big export
    assert len(digest) == 64
    anchors = real["reader"].anchors("network", 3)
    assert anchors and all(a["policy_hash"] == digest for a in anchors)                           # the witnesses anchored THIS policy


def test_learn_policy_reads_normal_destinations_from_a_clean_bundle(real, tmp_path, capsys):
    out = tmp_path / "learned.json"
    code = verifier_main(["learn-policy", "--bundles", *[str(p) for p in real["paths"].values()], "--out", str(out),
                          "--egress-threshold-bytes", str(THRESHOLD)])
    assert code == 0
    learned, _ = load_policy_file(out)
    assert learned["normal_destinations"] == [real["sink"]]
    assert learned["egress_threshold_bytes"] == THRESHOLD and learned["version"] == "learned-1"
    assert "policy hash" in capsys.readouterr().out


def test_policy_edited_after_anchoring_makes_every_policy_rule_cannot_verify(real, chain_copy, tmp_path):
    edited_policy = tmp_path / "policy.json"
    policy, _ = load_policy_file(real["policy"])
    policy["egress_threshold_bytes"] = 100_000_000            # an attacker raises the threshold so nothing is checked
    write_policy_file(edited_policy, policy)
    report = check(real, chain_copy, [str(p) for p in real["paths"].values()], rules="all", policy=edited_policy)
    for rule in ("C1", "C2", "C3"):
        found = by_rule(report, rule)
        assert found and {f.result for f in found} == {"CANNOT VERIFY"} and found[0].code == "policy", rule
        assert "not the policy that was in force" in found[0].evidence[0]
    assert report.warnings == []                                                  # C6 did not run either
    assert any("C6 was not run" in n for n in report.notices)
    assert by_rule(report, "C4", "MATCH")                                         # C4 reads no policy value
    assert report.exit_code == 2


def test_no_policy_file_means_the_policy_rules_cannot_verify(real, chain_copy):
    report = verify([str(p) for p in real["paths"].values()], chain_copy, rules="consistency")
    assert {f.result for f in by_rule(report, "C1")} == {"CANNOT VERIFY"} and by_rule(report, "C1")[0].code == "policy"


# ============================================================ A3: record of a large export deleted
def test_a3_app_record_of_a_large_export_deleted_is_a_c1_mismatch(real, chain_copy, tmp_path, capsys):
    def delete_big(b):
        b["entries"] = [e for e in b["entries"] if not (e["event_type"] == "outbound_call" and e["bytes"] == BIG)]
    paths = edited(real, tmp_path, app=delete_big)
    report = check(real, chain_copy, paths)
    c1 = by_rule(report, "C1", "MISMATCH")
    assert len(c1) == 1 and c1[0].subject == "network" and c1[0].code == "no-partner"
    assert "request %s" % real["big_request_id"][:8] in " ".join(c1[0].evidence)
    assert "App witness holds no record with this request id" in " ".join(c1[0].evidence)
    assert "demo-1" in c1[0].policy_version
    assert c1[0].answerable_by == "App witness operator"                             # the one who should hold the record
    assert report.exit_code == 1
    assert by_rule(report, "C2", "MATCH")                                            # the other direction is still fine
    sample = human_report(report, explain=True)
    assert "Policy version:" in sample and "Answerable by:" in sample
    with capsys.disabled():
        print("\n----- SAMPLE REPORT (A3: the App witness record of the large export was deleted) -----")
        print(sample)
        print("----- END SAMPLE REPORT -----")


# ============================================ A4: forged App record that matches real traffic
def test_a4_forged_app_record_matching_real_traffic_matches_but_warns_about_a_new_destination(real, chain_copy, tmp_path):
    """Built by editing COPIES of both the App and Network bundles (option 2): an exfiltration to a NEW destination is
    seen by the Network witness, and the attacker adds a matching record to the App log. C1 and C2 agree, as they must;
    C6 still warns, because the policy's list of normal destinations does not contain it."""
    new_dst, rid = "127.0.0.1:59999", "ab" * 16

    def add(role, etype, direction):
        def fn(b):
            template = max((e for e in b["entries"] if e["event_type"] == etype), key=lambda e: e["seq"])
            t = parse_ts(template["ts_utc"]) + 0.5
            e = dict(template, seq=template["seq"] + 1000, ts_utc=iso(t)[:-1] + ".500Z", request_id=rid, direction=direction,
                     dst=new_dst, bytes=3_000_000, result="ok:200")
            b["entries"].append(e)
        return fn
    paths = edited(real, tmp_path, app=add("app", "outbound_call", "out"), network=add("network", "connection", "out"))
    report = check(real, chain_copy, paths)
    assert [f.result for f in by_rule(report, "C1")] == ["MATCH"] and "2 of 2" in by_rule(report, "C1")[0].statement
    assert {f.result for f in by_rule(report, "C2")} == {"MATCH"}
    assert report.exit_code == 0                                                     # warnings do not change the verdict
    assert len(report.warnings) == 1 and report.warnings[0].code == "new-destination" and new_dst in report.warnings[0].statement
    assert any("never observed" in n and new_dst in n for n in report.notices)       # the Outside witness did not see it


# ============================================== A5: App activity with no network trace
def test_a5_app_activity_with_no_network_trace_is_a_c2_mismatch(real, chain_copy, tmp_path):
    def add_ghost(b):
        template = max((e for e in b["entries"] if e["event_type"] == "outbound_call"), key=lambda e: e["seq"])
        b["entries"].append(dict(template, seq=template["seq"] + 1000, request_id="cd" * 16, dst="127.0.0.1:59998", bytes=12_345,
                                 ts_utc=template["ts_utc"]))
    report = check(real, chain_copy, edited(real, tmp_path, app=add_ghost))
    c2 = by_rule(report, "C2", "MISMATCH")
    assert len(c2) == 1 and c2[0].subject == "app" and "Network witness holds no record with this request id" in " ".join(c2[0].evidence)
    assert report.exit_code == 1


# ===================================================== coverage: silent witness is CANNOT, not MISMATCH
def test_a_witness_that_was_silent_during_the_transfer_gives_cannot_verify_not_mismatch(real, chain_copy, tmp_path):
    big = next(e for e in load(real, "network")["entries"] if e["event_type"] == "connection" and e["bytes"] == BIG)
    t = parse_ts(big["ts_utc"])

    def silent(b):
        b["entries"] = [e for e in b["entries"] if not (e["event_type"] == "outbound_call" and e["bytes"] == BIG)]
        b["batches"] = [x for x in b["batches"] if abs(x["created_at"] - t) > 12]          # no signed batch near the transfer
    report = check(real, chain_copy, edited(real, tmp_path, app=silent))
    c1 = by_rule(report, "C1")
    assert [f.result for f in c1 if f.code == "no-cover"] == ["CANNOT VERIFY"]
    assert not by_rule(report, "C1", "MISMATCH")
    assert report.exit_code == 2


def test_a_missing_bundle_is_cannot_verify(real, chain_copy, tmp_path):
    paths = [str(p) for n, p in real["paths"].items() if n != "app"]
    report = check(real, chain_copy, paths)
    assert {f.result for f in by_rule(report, "C1")} == {"CANNOT VERIFY"} and by_rule(report, "C1")[0].code == "no-bundle"
    assert {f.result for f in by_rule(report, "C2")} == {"CANNOT VERIFY"}


# ======================================================= A8: outside records copied from network
def test_a8_outside_records_copied_from_network_are_cannot_verify_shared_input(real, chain_copy, tmp_path):
    network = load(real, "network")
    conns = sorted((e for e in network["entries"] if e["event_type"] == "connection" and e["direction"] == "out"), key=lambda e: e["seq"])

    def copy_from_network(b):
        flows = sorted((e for e in b["entries"] if e["event_type"] == "flow"), key=lambda e: e["seq"])
        assert len(flows) == len(conns) >= 3
        for f, c in zip(flows, conns):
            f["ts_utc"], f["bytes"], f["dst"] = c["ts_utc"], c["bytes"], c["dst"]
    report = check(real, chain_copy, edited(real, tmp_path, outside=copy_from_network))
    c3 = by_rule(report, "C3")
    assert [f.result for f in c3] == ["CANNOT VERIFY"] and c3[0].code == "shared-input"
    assert "heuristic" in c3[0].limitation and "shared input" in c3[0].statement.lower()
    assert report.exit_code == 2
    # the same rule on the untouched bundles is a MATCH: independent witnesses never agree to the millisecond
    honest = check(real, chain_copy, [str(p) for p in real["paths"].values()])
    assert by_rule(honest, "C3", "MATCH") and not by_rule(honest, "C3", "CANNOT VERIFY")


def test_outside_disagreeing_with_network_is_a_c3_mismatch(real, chain_copy, tmp_path):
    def halve(b):
        for e in b["entries"]:
            if e["event_type"] == "flow" and e["bytes"] == BIG:
                e["bytes"] = BIG // 2
    report = check(real, chain_copy, edited(real, tmp_path, outside=halve))
    c3 = by_rule(report, "C3", "MISMATCH")
    assert len(c3) == 1 and c3[0].code == "totals" and report.exit_code == 1


# ==================================================================== C6 on its own
def test_c6_warns_on_cumulative_bytes_without_changing_the_verdict(real, chain_copy, tmp_path):
    policy, _ = load_policy_file(real["policy"])
    # a policy with a lower 5-minute limit would have a different hash, so the cumulative limit is tested on the rule itself
    from verifier import consistency
    from verifier.rules import Run
    from verifier.model import load_bundle
    bundles = {n: load_bundle(str(p)) for n, p in real["paths"].items()}
    run = Run(bundles, chain_copy)
    run.load_chain()
    run.policy, run.policy_hash, run.policy_state = dict(policy, cumulative_threshold_bytes=1_000_000), "x" * 64, "ok"
    consistency.rule_c6(run)
    assert len(run.warnings) == 1 and run.warnings[0].code == "cumulative" and run.warnings[0].result == "WARNING"


# ====================================================================== C4 on a real chain
SEEDS = {"app": 21, "network": 22, "outside": 23}
MAX_GAP = 15                 # seconds each witness may be quiet on the test chain (one chain helper call takes about 4-5 s)
QUIET = 24                   # seconds the "stopped" witness stays quiet (longer than MAX_GAP)


def small_gap_chain(node_port, tmp_path, name):
    """A fresh deployment where each witness may be quiet for MAX_GAP seconds at most. Anchors are empty heartbeats."""
    from nacl.signing import SigningKey
    dep = tmp_path / (name + ".json")
    env = chain_env(node_port, dep)
    keys = {n: SigningKey(bytes([b]) * 32) for n, b in SEEDS.items()}
    out = helper(env, "setup-local", {"witnesses": {n: k.verify_key.encode().hex() for n, k in keys.items()}, "maxGapSeconds": MAX_GAP})
    assert out["ok"], out
    return env, dep


def heartbeat(env, name, batch_no):
    out = helper(env, "anchor", {"witnessId": name, "batchNo": batch_no, "firstSeq": 1, "lastSeq": 0, "entriesRoot": EMPTY,
                                 "receiptsRoot": EMPTY, "policyHash": "0x" + "00" * 32})
    assert out["ok"], out


class Keepers:
    """The Network and Outside witnesses keep sending heartbeats (one thread each) until the block ends."""

    def __init__(self, env, first_batch=2):
        self.env, self.first, self.stop = env, first_batch, threading.Event()
        self.threads = [threading.Thread(target=self._run, args=(n,), daemon=True) for n in ("network", "outside")]

    def _run(self, name):
        n = self.first
        while not self.stop.is_set():
            heartbeat(self.env, name, n)
            n += 1

    def __enter__(self):
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        for t in self.threads:
            t.join(timeout=60)


def first_heartbeats(env):
    ts = [threading.Thread(target=heartbeat, args=(env, n, 1)) for n in SEEDS]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def test_a6_a_stopped_witness_is_cannot_verify_with_the_silent_event_read_from_the_chain(node_port, tmp_path):
    env, dep = small_gap_chain(node_port, tmp_path, "a6")
    first_heartbeats(env)
    with Keepers(env):
        time.sleep(QUIET)                                # the App witness is stopped: it anchors nothing more
        flagged = helper(env, "admin", {"action": "flagSilence", "witnessId": "app"})
    assert flagged["ok"], flagged
    reader = HelperChainReader(HELPER, deployment_file=dep, env=env)
    events = reader.events()["events"]
    assert [e["type"] for e in events] == ["WitnessSilent"] and events[0]["witness"] == "app"
    report = verify([], reader, rules="C4")
    app = [f for f in report.findings if f.subject == "app"]
    assert {f.result for f in app} == {"CANNOT VERIFY"} and {f.code for f in app} == {"gap", "silent-event"}
    assert not [f for f in report.findings if f.result == "MISMATCH"]                    # silence is never a mismatch
    assert {f.result for f in report.findings if f.subject in ("network", "outside")} == {"MATCH"}
    silent = next(f for f in app if f.code == "silent-event")
    assert silent.anchor_tx == events[0]["tx_hash"] and "WitnessSilent event read from the chain" in " ".join(silent.evidence)
    assert report.exit_code == 2


def test_a7_an_approved_pause_is_a_notice_not_a_silence_finding(node_port, tmp_path):
    env, dep = small_gap_chain(node_port, tmp_path, "a7")
    first_heartbeats(env)
    with Keepers(env):
        paused = helper(env, "admin", {"action": "beginPause", "witnessId": "app", "seconds": 180, "reason": "planned maintenance"})
        assert paused["ok"], paused                      # two owners made the identical call
        time.sleep(QUIET)                                # the App witness is quiet, with permission
        refused = helper(env, "admin", {"action": "flagSilence", "witnessId": "app"})
        assert not refused["ok"]                         # the contract does not allow a flag during a pause
        heartbeat(env, "app", 2)                         # it comes back before the pause ends
    reader = HelperChainReader(HELPER, deployment_file=dep, env=env)
    report = verify([], reader, rules="C4")
    assert {f.result for f in report.findings} == {"MATCH"} and report.exit_code == 0
    assert any("planned pause" in n and "App witness" in n and "not counted as silence" in n for n in report.notices)
    assert not [e for e in reader.events()["events"] if e["type"] == "WitnessSilent"]


def test_a_quiet_witness_without_any_pause_is_still_flagged_by_the_gap_alone(node_port, tmp_path):
    env, dep = small_gap_chain(node_port, tmp_path, "gap")
    first_heartbeats(env)
    with Keepers(env):
        time.sleep(QUIET)
    report = verify([], HelperChainReader(HELPER, deployment_file=dep, env=env), rules="C4")
    app = [f for f in report.findings if f.subject == "app"]
    assert [f.code for f in app] == ["gap"] and app[0].result == "CANNOT VERIFY" and "allows %d s" % MAX_GAP in app[0].statement
    assert {f.result for f in report.findings if f.subject != "app"} == {"MATCH"}


# ================================================================ the flush itself
def test_flush_gives_peers_the_newest_entries(tmp_path):
    """In-memory witnesses: until flush() runs, the peers have heard nothing about the newest entries."""
    from test_witness import Wire, add, make
    wire = Wire()
    ws = {n: make(tmp_path, n, wire=wire) for n in ("app", "network", "outside")}
    for w in ws.values():
        add(w, 3)
    for peer in ("network", "outside"):
        assert ws[peer].store.latest_authenticator_of("app") is None
    answer = ws["app"].flush()
    assert answer == {"complete": True, "peers_missing": []}
    newest = ws["app"].store.last_entry()["seq"]
    for peer in ("network", "outside"):
        assert ws[peer].store.latest_authenticator_of("app")["seq"] == newest


def test_prepare_shutdown_writes_one_marker_and_stop_does_not_add_a_second(tmp_path):
    from test_witness import Wire, add, make
    wire = Wire()
    ws = {n: make(tmp_path, n, wire=wire) for n in ("app", "network", "outside")}
    add(ws["app"], 2)
    ws["app"].prepare_shutdown()
    ws["app"].prepare_shutdown()                           # safe to repeat
    ws["app"].stop()
    entries = [json.loads(j) for (j,) in sqlite3.connect(str(tmp_path / "app.db")).execute("SELECT entry_json FROM entries ORDER BY seq")]
    assert sum(1 for e in entries if e["event_type"] == "shutdown") == 1 and entries[-1]["event_type"] == "shutdown"
    for peer in ("network", "outside"):                    # the peers vouch for the marker itself
        assert ws[peer].store.latest_authenticator_of("app")["seq"] == entries[-1]["seq"]
