"""Attack demonstration: "delete evidence" (attack A3, demo step 2).

Runs the REAL QuickPay stack end to end: the app, the gateway, the outside capture, all three
LogSabha witnesses, the baseline, and a real local Hardhat chain. A normal export happens,
then one large export (above the policy's threshold). Then an attacker who holds ONLY the App
witness's own key file (root on the app machine -- the baseline lives there too, so its key is
exposed the same way) deletes that export's record from the App witness's own database and
reseals its own chain so it is perfectly self-consistent (see attacks/forge.py). The Network
and Outside witnesses -- a different machine in this model -- are never touched.

Two timing variants:
  fast  - the tamper happens BEFORE the next scheduled anchor (every 30 s by default).
  slow  - the tamper happens AFTER that anchor already landed on the chain.

Both verifiers then run over freshly exported evidence, and the two verdicts are printed
side by side. One JSON result file is written per run, under attacks/results/.

  python -m attacks.delete_evidence --variant fast
  python -m attacks.delete_evidence --variant slow
  python -m attacks.delete_evidence                      (runs both, one after another)

Nothing here holds a real secret: every key is a throw-away file made for this one run, and
the chain is a local, disposable Hardhat node. Keys are never printed.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from nacl.signing import SigningKey

from baseline import BaselineLog, verify_baseline
from baseline.export import write_bundle as write_baseline_bundle
from launcher import Stack
from logsabha_core.policy import write_policy_file
from verifier.chain import HelperChainReader
from verifier.rules import verify as verify_logsabha
from witness.anchor import ChainAnchorBackend
from witness.export import build_bundle as build_witness_bundle

from attacks.forge import delete_and_reseal

REPO = Path(__file__).resolve().parent.parent.parent
HELPER = str(REPO / "chain" / "cli.js")
SOLIDITY = str(REPO / "Solidity")
RESULTS_DIR = Path(__file__).resolve().parent / "results"
FAKE_PASSWORD = "quickpay-attack-demo-password"
ANCHOR_INTERVAL = 30.0
BIG_BYTES = 3_000_000
THRESHOLD = 1_000_000
SEEDS = {"app": 21, "network": 22, "outside": 23}


def now_iso():
    t = time.time()
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + ("%03dZ" % (t % 1 * 1000)), t


def log(events, text):
    stamp, t = now_iso()
    print("[%s] %s" % (stamp, text))
    events.append({"at": stamp, "epoch": t, "text": text})


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def rpc_ready(port):
    try:
        r = requests.post("http://127.0.0.1:%d" % port, timeout=1,
                          json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []})
        return r.json().get("result") == "0x7a69"
    except (requests.RequestException, ValueError):
        return False


def kill_tree(proc):
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    else:
        proc.kill()
    proc.wait(timeout=15)


def start_node(log_path):
    port = free_port()
    npx = shutil.which("npx")
    if not npx:
        raise RuntimeError("npx not found; cannot start a local Hardhat node")
    proc = subprocess.Popen([npx, "hardhat", "node", "--hostname", "127.0.0.1", "--port", str(port)],
                            cwd=SOLIDITY, stdout=open(log_path, "wb"), stderr=subprocess.STDOUT)
    deadline = time.time() + 90
    while time.time() < deadline and not rpc_ready(port):
        assert proc.poll() is None, "hardhat node exited early; see " + str(log_path)
        time.sleep(0.5)
    assert rpc_ready(port), "hardhat node did not start"
    return proc, port


def chain_helper(env, command, payload=None):
    proc = subprocess.run(["node", HELPER, command], input=json.dumps(payload) if payload is not None else None,
                          capture_output=True, text=True, timeout=120, env=env)
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    if not out.get("ok"):
        raise RuntimeError("chain helper %s failed: %s" % (command, out.get("error")))
    return out


def respawn_witness(stack, name):
    """Start a NEW process for one witness, with the SAME arguments Stack.start() used. Used
    after the attacker has killed the process to edit its database file."""
    stack.procs = [(n, p, s) for n, p, s in stack.procs if n != "witness_" + name]
    anchor = stack.cfg.get("anchor", {})
    host, port = stack.bind(stack.cfg["witnesses"][name])
    args = ["witness", "--role", name, "--name", name, "--host", host, "--port", str(port),
           "--key-file", str(stack.keys_dir / (name + ".seed")), "--db", str(stack.db_dir / (name + ".witness.db")),
           "--anchor-file", str(stack.data / (name + ".anchors.jsonl")), "--backend", anchor.get("backend", "fake"),
           "--anchor-interval", str(anchor.get("interval_seconds", 30)),
           "--receipt-grace", str(anchor.get("receipt_grace_seconds", 10)),
           "--batch-interval", str(stack.cfg.get("batch_interval_seconds", 2))]
    if stack.cfg.get("policy_file"):
        args += ["--policy-file", str(stack.cfg["policy_file"])]
    if anchor.get("backend") == "chain":
        args += ["--confirmations", str(anchor.get("confirmations", 3))]
        if anchor.get("deployment_file"):
            args += ["--deployment-file", str(anchor["deployment_file"])]
    for other in ("app", "network", "outside"):
        if other != name:
            args += ["--peer", "%s=%s=%s" % (other, stack.witness_url(other), stack.public_keys[other])]
    proc, ready = stack._spawn("witness_" + name, args, stack.witness_url(name) + "/status")
    stack._wait_ready(name, proc, ready, timeout=60)


def find_seq(entries, event_type, request_id):
    for e in entries:
        if e.get("event_type") == event_type and e.get("request_id") == request_id:
            return e["seq"]
    return None


def run_variant(variant, out_dir, events):
    log(events, "=== delete-evidence attack: variant '%s' ===" % variant)
    out_dir.mkdir(parents=True, exist_ok=True)
    data = out_dir / "data"
    data.mkdir(exist_ok=True)

    node_proc, rpc_port = start_node(out_dir / "hardhat-node.log")
    log(events, "local Hardhat node up on 127.0.0.1:%d" % rpc_port)
    stack = None
    baseline = None
    try:
        dep = out_dir / "deployment.json"
        env = dict(os.environ, NETWORK="localhost", LOCAL_RPC_URL="http://127.0.0.1:%d" % rpc_port,
                  LOCAL_CHAIN_ID="31337", CHAIN_DEPLOYMENT_FILE=str(dep))
        app_key, network_key, outside_key = (SigningKey(bytes([b]) * 32) for b in SEEDS.values())
        baseline_key = SigningKey.generate()
        chain_helper(env, "setup-local", {
            "witnesses": {"app": app_key.verify_key.encode().hex(), "network": network_key.verify_key.encode().hex(),
                          "outside": outside_key.verify_key.encode().hex()},
            "maxGapSeconds": 600})
        chain_helper(env, "registerWitness", {"id": "baseline", "edPubKey": baseline_key.verify_key.encode().hex(),
                                              "maxGapSeconds": 600})
        log(events, "chain set up: app, network, outside and baseline all registered")

        sink_port, gateway_port, app_port = free_port(), free_port(), free_port()
        wports = {n: free_port() for n in ("app", "network", "outside")}
        sink = "127.0.0.1:%d" % sink_port
        policy_path = out_dir / "policy.json"
        write_policy_file(policy_path, {"version": "attack-demo-1", "normal_destinations": [sink],
                                        "egress_threshold_bytes": THRESHOLD})

        config = {
            "label": "SIMULATED SEPARATION (attack demo): one laptop, separate ports",
            "data_dir": str(data), "batch_interval_seconds": 2, "policy_file": str(policy_path),
            "anchor": {"backend": "chain", "interval_seconds": ANCHOR_INTERVAL, "receipt_grace_seconds": 3,
                      "confirmations": 1, "deployment_file": str(dep)},
            "witnesses": {n: {"host": "127.0.0.1", "port": p} for n, p in wports.items()},
            "app": {"host": "127.0.0.1", "port": app_port, "demo_password": FAKE_PASSWORD, "customers": 60},
            "gateway": {"host": "127.0.0.1", "port": gateway_port},
            "outside": {"mode": "sink", "host": "127.0.0.1", "port": sink_port},
        }
        stack = Stack(config)
        for d in (stack.keys_dir, stack.logs_dir, stack.run_dir, stack.db_dir):
            d.mkdir(parents=True, exist_ok=True)
        for name, key in (("app", app_key), ("network", network_key), ("outside", outside_key)):
            (stack.keys_dir / (name + ".seed")).write_text(key.encode().hex())
            stack.public_keys[name] = key.verify_key.encode().hex()
        # the witness subprocesses read the local chain's address from THEIR OWN environment
        # (they are spawned with os.environ, not with the `env` dict built above), so it must
        # go into os.environ here, and come back out again once this run is done.
        saved_env = {k: os.environ.get(k) for k in ("NETWORK", "LOCAL_RPC_URL", "LOCAL_CHAIN_ID", "CHAIN_DEPLOYMENT_FILE")}
        os.environ.update({k: env[k] for k in saved_env})
        stack.start(timeout=90)
        log(events, "the real stack is up: app, gateway, outside capture, three witnesses")

        baseline_backend = ChainAnchorBackend("baseline", HELPER, deployment_file=dep, env=env)
        baseline = BaselineLog(baseline_key, "baseline", data / "baseline.db", baseline_backend)
        baseline.start(ANCHOR_INTERVAL)
        log(events, "the baseline is up: a single hash chain, anchoring every %ss, no peers" % ANCHOR_INTERVAL)

        s = requests.Session()
        s.trust_env = False
        r = s.post(stack.app_url + "/login", json={"username": "analyst", "password": FAKE_PASSWORD}, timeout=10)
        r.raise_for_status()
        baseline.add_entry("login", r.headers["X-Request-ID"], "in", "/login", len(r.content), "ok")
        auth = {"Authorization": "Bearer " + r.json()["token"]}
        r = s.get(stack.app_url + "/customers", params={"limit": 5}, headers=auth, timeout=10)
        baseline.add_entry("query", r.headers["X-Request-ID"], "local", "customers", len(r.content), "ok")
        log(events, "normal activity done: login + one query")

        anchor_landed_at = time.time() + ANCHOR_INTERVAL        # the next scheduled anchor, for both app and baseline
        r = s.post(stack.app_url + "/export", json={"destination_url": "http://%s/exfil" % sink, "bytes": BIG_BYTES,
                                                     "purpose": "partner-report"}, headers=auth, timeout=120)
        r.raise_for_status()
        big_request_id = r.headers["X-Request-ID"]
        log(events, "the BIG export happened: %d bytes to %s, request %s (above the %d byte threshold)" % (
            BIG_BYTES, sink, big_request_id[:8], THRESHOLD))
        baseline.add_entry("outbound_call", big_request_id, "out", sink, BIG_BYTES, "ok:200")
        seconds_until_anchor = anchor_landed_at - time.time()
        log(events, "tamper window: the next anchor for the App witness and the baseline is due in about %.1fs" %
            seconds_until_anchor)

        time.sleep(2)              # let the App witness's own batch-close pick the entry up (2 s batch interval)
        app_entries = build_witness_bundle(stack.db_path("app"))["entries"]
        app_seq = find_seq(app_entries, "outbound_call", big_request_id)
        assert app_seq is not None, "the export's App witness entry was not found yet"
        baseline_seq = next(e["seq"] for e in baseline.store.all_entries() if e["request_id"] == big_request_id)
        reader = HelperChainReader(HELPER, deployment_file=dep, env=env)

        if variant == "slow":
            log(events, "variant 'slow': waiting for the anchor covering this entry to land on the chain first...")
            deadline = time.time() + ANCHOR_INTERVAL * 3
            while time.time() < deadline:
                keys = reader.witness_keys()
                if keys.get("app", {}).get("last_seq", 0) >= app_seq and \
                        keys.get("baseline", {}).get("last_seq", 0) >= baseline_seq:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("the anchor never landed in time for the 'slow' variant")
            already_anchored = True
            log(events, "the anchor landed BEFORE the tamper (seq %d is now on chain for the App witness)" % app_seq)
        else:
            keys = reader.witness_keys()
            already_anchored = keys.get("app", {}).get("last_seq", 0) >= app_seq
            if already_anchored:
                log(events, "NOTE: by the time we checked, the real anchor had ALREADY covered seq %d -- "
                            "this 'fast' attempt landed too slow by chance; reporting what actually happened" % app_seq)
            else:
                log(events, "tampering now, BEFORE the next anchor (seq %d is NOT yet on chain)" % app_seq)

        stack.kill_service("witness_app")
        baseline.stop()
        log(events, "attacker action: stopped the App witness and the baseline (root on the app machine)")
        delete_and_reseal(stack.db_path("app"), app_key, [app_seq])
        delete_and_reseal(data / "baseline.db", baseline_key, [baseline_seq])
        log(events, "attacker action: deleted the export record and resealed the chain (App witness AND baseline; "
                    "the Network and Outside witnesses were never touched)")

        respawn_witness(stack, "app")
        baseline = BaselineLog(baseline_key, "baseline", data / "baseline.db", baseline_backend)
        baseline.start(ANCHOR_INTERVAL)
        log(events, "both resumed normally and will anchor whatever their (now tampered) files hold")

        time.sleep(ANCHOR_INTERVAL + 6)                         # let the next real anchor happen
        baseline.anchor_now()                                   # one more explicit anchor, like a flush, before stopping
        baseline.stop()
        outcome = stack.stop()
        log(events, "clean stop: %s" % outcome)

        (data / "bundles").mkdir(exist_ok=True)
        bundle_paths = stack.export_bundles(data / "bundles", flush=True)
        write_baseline_bundle(data / "baseline.db", data / "bundles" / "baseline.bundle.json")
        log(events, "evidence exported for all four logs")

        reader = HelperChainReader(HELPER, deployment_file=dep, env=env)
        baseline_bundle = json.loads((data / "bundles" / "baseline.bundle.json").read_text(encoding="utf-8"))
        baseline_result = verify_baseline(baseline_bundle, reader)
        logsabha_report = verify_logsabha([str(p) for p in bundle_paths.values()], reader,
                                          policy_path=str(policy_path), rules="all")
        return finish(variant, already_anchored, events, baseline_result, logsabha_report, app_seq)
    finally:
        if baseline is not None:
            try:
                baseline.stop()
            except Exception:
                pass
        if stack is not None and stack.procs:
            try:
                stack.stop()
            except Exception:
                pass
        for k, v in locals().get("saved_env", {}).items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        kill_tree(node_proc)


def finish(variant, already_anchored, events, baseline_result, logsabha_report, app_seq):
    fired = sorted({f.rule + ":" + f.result for f in logsabha_report.findings if f.result != "MATCH"})
    print()
    print("=" * 72)
    print("SIDE BY SIDE - attack 'delete-evidence', variant '%s'" % variant)
    print("=" * 72)
    print("%-22s %-16s %s" % ("", "Baseline (B1,B2)", "LogSabha (overall)"))
    print("%-22s %-16s %s" % ("Verdict", baseline_result["overall"], logsabha_report.overall))
    print()
    print("Baseline checks:")
    for c in baseline_result["checks"]:
        print("  %s %-14s %s" % (c["rule"], c["result"], c["detail"]))
    print("LogSabha findings that are not MATCH:")
    for f in logsabha_report.findings:
        if f.result != "MATCH":
            print("  %s %-14s %s" % (f.rule, f.result, f.statement))
    print("=" * 72)

    # what SHOULD happen depends on whether the tamper actually beat the anchor, not on the --variant label
    # someone chose before the race ran: "fast" can land "too slow" by chance, and vice versa for "slow" never does
    # (the script waits for it), so this is judged from what was actually observed.
    expected = ("MISMATCH", "MISMATCH") if already_anchored else ("MATCH", "MISMATCH")
    as_expected = (baseline_result["overall"], logsabha_report.overall) == expected
    print("Tamper landed %s the anchor. Expected (baseline %s, LogSabha %s). Matched? %s" % (
        "AFTER" if already_anchored else "BEFORE", expected[0], expected[1], "YES" if as_expected else "NO"))

    result = {
        "attack_id": "delete-evidence", "variant": variant, "already_anchored_before_tamper": already_anchored,
        "dropped_app_seq": app_seq, "baseline_verdict": baseline_result["overall"],
        "baseline_checks": baseline_result["checks"], "logsabha_verdict": logsabha_report.overall,
        "logsabha_exit_code": logsabha_report.exit_code, "rule_ids_that_fired": fired,
        "expected": expected, "as_expected": as_expected, "timeline": events,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result_path = RESULTS_DIR / ("delete-evidence-%s-%s.json" % (variant, stamp))
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print("Result written to %s" % result_path)
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description="Attack demonstration: delete evidence (attack A3)")
    p.add_argument("--variant", choices=("fast", "slow", "both"), default="both")
    args = p.parse_args(argv)
    variants = ("fast", "slow") if args.variant == "both" else (args.variant,)
    results = []
    for variant in variants:
        events = []
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = RESULTS_DIR / ("run-%s-%s" % (variant, stamp))
        results.append(run_variant(variant, out_dir, events))
    return 0


if __name__ == "__main__":
    sys.exit(main())
