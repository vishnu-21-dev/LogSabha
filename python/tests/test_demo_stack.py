"""Step F: the QuickPay app, the gateway, the outside capture and the launcher, as real processes.

Everything here is "simulated separation": one laptop, separate ports.
The tests run in file order on ONE shared stack: the gateway is stopped near the end and the
clean stop is last.
"""
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests
from nacl.signing import VerifyKey

import clean_run
from launcher import Stack
from logsabha_core import ENTRY_FIELDS, verify_chain
from outside.capture import FlowTable
from test_witness_processes import free_port

PY_DIR = Path(__file__).resolve().parent.parent
FAKE_PASSWORD = "quickpay-test-fake-password"


def http():
    s = requests.Session()
    s.trust_env = False
    return s


def read_entries(db_path):
    con = sqlite3.connect(str(db_path), timeout=10)
    try:
        return [json.loads(r[0]) for r in con.execute("SELECT entry_json FROM entries ORDER BY seq")]
    finally:
        con.close()


def wait_for(predicate, timeout=25, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.3)
    raise AssertionError("timed out waiting for " + what)


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    data = tmp_path_factory.mktemp("demo")
    config = {
        "label": "SIMULATED SEPARATION (test): one laptop, separate ports",
        "data_dir": str(data),
        "batch_interval_seconds": 2,
        "anchor": {"backend": "fake", "interval_seconds": 6, "receipt_grace_seconds": 4},
        "witnesses": {n: {"host": "127.0.0.1", "port": free_port()} for n in ("app", "network", "outside")},
        "app": {"host": "127.0.0.1", "port": free_port(), "demo_password": FAKE_PASSWORD, "customers": 60},
        "gateway": {"host": "127.0.0.1", "port": free_port()},
        "outside": {"mode": "sink", "host": "127.0.0.1", "port": free_port()},
    }
    s = Stack(config).start(timeout=60)
    yield s
    s.stop()


@pytest.fixture(scope="module")
def session(stack):
    """A logged-in QuickPay session (the login itself goes through the app)."""
    c = http()
    r = c.post(stack.app_url + "/login", json={"username": "analyst", "password": FAKE_PASSWORD}, timeout=10)
    assert r.status_code == 200
    c.headers["Authorization"] = "Bearer " + r.json()["token"]
    return c


@pytest.fixture(scope="module")
def clean(stack):
    """One clean run through the app: login, 3 queries, a normal export, a nightly-backup export."""
    sink = urlsplit(stack.outside_url).netloc
    steps = clean_run.run(stack.app_url, "analyst", FAKE_PASSWORD,
                          export_url="http://%s/partner-report" % sink, backup_url="http://%s/nightly-backup" % sink)
    return {"steps": steps, "sink": sink}


def all_entries(stack):
    return {n: read_entries(stack.db_path(n)) for n in ("app", "network", "outside")}


# ------------------------------------------------------------------ request ids
def test_request_ids_are_fresh_and_a_client_supplied_id_is_overwritten(stack, session):
    forged = "a" * 32
    seen = []
    for i in range(10):
        r = session.get(stack.app_url + "/customers", params={"limit": 3, "request_id": forged},
                        headers={"X-Request-ID": forged}, timeout=10)
        assert r.status_code == 200
        seen.append(r.headers["X-Request-ID"])
    login = http().post(stack.app_url + "/login", headers={"X-Request-ID": forged}, timeout=10,
                        json={"username": "analyst", "password": FAKE_PASSWORD, "request_id": forged})
    seen.append(login.headers["X-Request-ID"])

    assert all(re.fullmatch(r"[0-9a-f]{32}", x) for x in seen)          # 128 bits, as hex
    assert len(set(seen)) == len(seen)                                  # every request got a fresh one
    assert forged not in seen                                           # the client's id was overwritten

    # what the witness recorded is the app's id, never the client's
    app_ids = lambda: {e["request_id"] for e in read_entries(stack.db_path("app"))}
    wait_for(lambda: set(seen) <= app_ids(), what="the App witness to hold the new request ids")
    for name, entries in all_entries(stack).items():
        assert forged not in {e["request_id"] for e in entries}, name


# --------------------------------------------------------------------- privacy
ALLOWED_EVENT_TYPES = {"login", "query", "export", "outbound_call", "connection", "flow", "restart", "shutdown"}
RESULT_SHAPE = re.compile(r"^(ok|denied|accepted|partial|error|first_boot|after_shutdown|after_crash|clean)([:;][A-Za-z0-9=._:-]*)?$")


def test_no_entry_contains_customer_rows_or_personal_data(stack, session, clean):
    import demo_app.db as db
    con = db.connect(stack.db_dir / "quickpay.db")
    customers = [dict(r) for r in con.execute("SELECT name, email, city FROM customers")]
    con.close()
    forbidden = {c["name"] for c in customers} | {c["email"] for c in customers} | {c["city"] for c in customers}
    forbidden |= {"analyst", "auditor", FAKE_PASSWORD, session.headers["Authorization"][7:], "example.invalid"}

    # sanity: the query answer really does hold personal data, so this test could catch a leak
    body = session.get(stack.app_url + "/customers", params={"limit": 5}, timeout=10).text
    assert any(c["name"] in body for c in customers)

    wait_for(lambda: len(read_entries(stack.db_path("outside"))) >= 3, what="entries to arrive")
    checked = 0
    for name, entries in all_entries(stack).items():
        assert entries, name
        for e in entries:
            assert set(e) == set(ENTRY_FIELDS)                           # no extra fields at all
            assert e["event_type"] in ALLOWED_EVENT_TYPES
            assert RESULT_SHAPE.match(e["result"]), e["result"]
            assert e["dst"] is None or re.fullmatch(r"(/login|customers|[0-9.]+:\d+)", e["dst"]), e["dst"]
            assert isinstance(e["bytes"], int)
            text = json.dumps(e)
            for secret in forbidden:
                assert secret not in text, "%r leaked into a %s entry" % (secret, name)
            checked += 1
    print("\n  privacy check: %d entries in 3 witnesses, none holds a name, email, city, username, password or token" % checked)


# ----------------------------------------------------------------- clean run
def test_clean_run_all_three_witnesses_hold_matching_records_for_the_export(stack, clean):
    exports = [s for s in clean["steps"] if s["step"] in ("export", "nightly-backup")]
    assert len(exports) == 2
    ids = {s["request_id"] for s in exports}

    def collect():
        e = all_entries(stack)
        found = {
            "app": {x["request_id"]: x for x in e["app"] if x["event_type"] == "outbound_call" and x["request_id"] in ids},
            "network": {x["request_id"]: x for x in e["network"] if x["event_type"] == "connection" and x["request_id"] in ids},
            "outside": {x["request_id"]: x for x in e["outside"] if x["event_type"] == "flow" and x["request_id"] in ids},
        }
        return found if all(len(v) == 2 for v in found.values()) else None

    found = wait_for(collect, what="each witness to hold both exports")

    print("\n  CLEAN RUN: what each witness recorded for the two exports (simulated separation, one laptop)")
    print("  %-34s %-12s %11s %13s %13s" % ("request_id", "step", "app bytes", "network bytes", "outside bytes"))
    for s in exports:
        rid = s["request_id"]
        a, n, o = found["app"][rid], found["network"][rid], found["outside"][rid]
        print("  %-34s %-12s %11d %13d %13d" % (rid, s["step"], a["bytes"], n["bytes"], o["bytes"]))
        assert a["bytes"] == n["bytes"] == o["bytes"] == s["bytes"]                  # all three agree exactly
        assert a["dst"] == n["dst"] == o["dst"] == clean["sink"]                     # and about the same destination
        assert a["direction"] == n["direction"] == "out" and o["direction"] == "in"
        assert a["result"].startswith("ok") and n["result"].startswith("ok") and o["result"].startswith("ok")

    # join rate: how many app outbound events had a network event with the same request_id
    entries = all_entries(stack)
    app_out = [e for e in entries["app"] if e["event_type"] == "outbound_call"]
    net_ids = {e["request_id"] for e in entries["network"] if e["event_type"] == "connection"}
    out_ids = {e["request_id"] for e in entries["outside"] if e["event_type"] == "flow"}
    matched_net = sum(1 for e in app_out if e["request_id"] in net_ids)
    matched_out = sum(1 for e in app_out if e["request_id"] in out_ids)
    app_total = len([e for e in entries["app"] if e["event_type"] not in ("restart", "shutdown")])
    print("  join rate, app outbound calls with a network event (same request_id): %d/%d = %d%%" % (
        matched_net, len(app_out), 100 * matched_net // len(app_out)))
    print("  join rate, app outbound calls with an outside event (same request_id): %d/%d = %d%%" % (
        matched_out, len(app_out), 100 * matched_out // len(app_out)))
    print("  (the other %d app events are logins, queries and export requests: they stay inside the app)" % (
        app_total - len(app_out)))
    assert matched_net == matched_out == len(app_out) and len(app_out) >= 2

    # every witness's own chain is valid and signed by its own key
    for name in ("app", "network", "outside"):
        key = VerifyKey(bytes.fromhex(stack.public_keys[name]))
        assert verify_chain(entries[name], key).valid, name


# ---------------------------------------------------------- outside independence
def test_outside_capture_keeps_working_when_the_gateway_is_stopped(stack, session):
    sink = urlsplit(stack.outside_url).netloc
    before = all_entries(stack)
    stack.kill_service("gateway")
    with pytest.raises(requests.RequestException):
        http().get(stack.gateway_url + "/status", timeout=2)

    # the app can no longer reach the outside world (it must go through the gateway) ...
    r = session.post(stack.app_url + "/export", timeout=30,
                     json={"destination_url": "http://%s/blocked" % sink, "bytes": 5000, "purpose": "test"})
    assert r.status_code == 502
    failed_id = r.headers["X-Request-ID"]
    wait_for(lambda: any(e["request_id"] == failed_id and e["result"] == "error:gateway_unreachable"
                         for e in read_entries(stack.db_path("app"))), what="the app to log the failed call")

    # ... but the outside capture is its own observation point and keeps recording
    direct = http().post("http://%s/direct" % sink, data=b"x" * 12345, timeout=10)
    assert direct.status_code == 200 and direct.json() == {"received": 12345}
    flow = wait_for(lambda: next((e for e in read_entries(stack.db_path("outside"))
                                  if e["event_type"] == "flow" and e["bytes"] == 12345), None),
                    what="the Outside witness to record the direct flow")
    assert flow["request_id"] == "" and flow["dst"] == sink and flow["direction"] == "in"
    assert http().get(stack.outside_url + "/__stats", timeout=5).json()["per_source"]["127.0.0.1"]["bytes"] >= 12345

    # the Network witness saw none of it: the traffic went around the gateway
    time.sleep(3)
    net_after = read_entries(stack.db_path("network"))
    assert not any(e["event_type"] == "connection" and e["bytes"] == 12345 for e in net_after)
    print("\n  gateway stopped: outside witness still recorded a %d-byte flow; network witness recorded nothing for it" % flow["bytes"])
    assert len(before["network"]) <= len(net_after)


# --------------------------------------------------------------------- static checks
def test_the_outside_package_never_mentions_the_gateway():
    for path in (PY_DIR / "outside").glob("*.py"):
        assert "gateway" not in path.read_text(encoding="utf-8").lower(), path.name


def test_no_address_or_port_is_hard_coded_in_the_new_components():
    ip = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    files = [p for d in ("demo_app", "gateway", "outside", "launcher", "svc") for p in (PY_DIR / d).glob("*.py")]
    files.append(PY_DIR / "clean_run.py")
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert not ip.search(text), "IP address literal in " + path.name
        assert "localhost" not in text.lower(), "localhost in " + path.name
        assert not re.search(r":\d{4,5}\b", text), "port literal in " + path.name


# -------------------------------------------------------------- scapy mode (optional)
def test_flow_table_adds_up_bytes_per_flow_and_ignores_other_ports():
    t = FlowTable(watch_ports=[9000], idle_seconds=2.0)
    t.add_packet("10.0.0.1", 5000, "10.0.0.2", 9000, 100, False, now=0)
    t.add_packet("10.0.0.1", 5000, "10.0.0.2", 9000, 250, True, now=0.1)       # FIN
    t.add_packet("10.0.0.1", 5001, "10.0.0.2", 9000, 0, False, now=0)          # handshake only
    t.add_packet("10.0.0.1", 5002, "10.0.0.2", 7777, 999, False, now=0)        # not a watched port
    assert t.collect_finished(now=0.2) == []                                   # just closed: wait a moment
    done = t.collect_finished(now=1.0)
    assert done == [(("10.0.0.1", 5000, "10.0.0.2", 9000), 350)]
    assert t.collect_finished(now=10) == []                                    # the empty handshake flow is dropped quietly


def test_scapy_mode_records_a_real_flow_on_the_loopback_interface():
    from outside.capture import run_capture

    class Recorder:
        def __init__(self):
            self.rows = []

        def post(self, *row):
            self.rows.append(row)

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    port = free_port()

    class Dest(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", port), Dest)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    rec, stop, failure = Recorder(), threading.Event(), []
    iface = r"\Device\NPF_Loopback" if sys.platform == "win32" else "lo"

    def go():
        try:
            run_capture([port], iface, rec, stop, idle_seconds=1.0)
        except Exception as err:
            failure.append(err)

    t = threading.Thread(target=go, daemon=True)
    t.start()
    time.sleep(3)
    try:
        if failure:
            pytest.skip("packet capture is not available here: %s: %s" % (type(failure[0]).__name__, failure[0]))
        http().post("http://127.0.0.1:%d/x" % port, data=b"y" * 100_000, timeout=10)
        deadline = time.time() + 15
        while time.time() < deadline and not rec.rows:
            time.sleep(0.3)
        if not rec.rows and failure:
            pytest.skip("packet capture failed: %s" % failure[0])
        assert rec.rows, "scapy saw no flow"
        event_type, request_id, direction, dst, size, result = rec.rows[0]
        assert (event_type, request_id, direction, dst) == ("flow", "", "in", "127.0.0.1:%d" % port)
        assert 100_000 <= size < 101_500           # payload plus HTTP headers
        print("\n  scapy mode: captured a real flow of %d payload bytes on the loopback interface" % size)
    finally:
        stop.set()
        server.shutdown()


# ----------------------------------------------------------------------- clean stop (last)
def test_clean_stop_writes_shutdown_markers_and_every_service_exits(stack):
    for name in ("app", "network", "outside"):
        assert read_entries(stack.db_path(name))[-1]["event_type"] != "shutdown"
    outcome = stack.stop()
    print("\n  stop outcome:", outcome)
    for service in ("demo_app", "outside_capture", "witness_app", "witness_network", "witness_outside"):
        assert outcome[service] == "clean", outcome
    assert outcome["gateway"].startswith("exited")            # it was stopped on purpose earlier in this file
    for name in ("app", "network", "outside"):
        last = read_entries(stack.db_path(name))[-1]
        assert (last["event_type"], last["result"]) == ("shutdown", "clean"), name
    for url in (stack.app_url, stack.witness_url("app"), stack.outside_url):
        with pytest.raises(requests.RequestException):
            http().get(url + "/status", timeout=2)
