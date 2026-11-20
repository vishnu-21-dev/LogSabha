"""Starts and stops the whole demo: 3 witnesses, the QuickPay app, the gateway and the outside capture.

Everything is read from one config file (see demo.config.json). All keys come from key files:
a missing key file is created once (and never overwritten); nothing secret is printed.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

from witness.keys import load_signing_key, write_new_key_file

PYTHON_DIR = Path(__file__).resolve().parent.parent
WITNESS_NAMES = ("app", "network", "outside")
BANNER = "SIMULATED SEPARATION: every component runs on this one laptop, on separate ports"


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class Stack:
    def __init__(self, config):
        self.cfg = config
        self.label = config.get("label", BANNER)
        self.data = Path(config["data_dir"]).resolve()
        self.keys_dir, self.logs_dir = self.data / "keys", self.data / "logs"
        self.run_dir, self.db_dir = self.data / "run", self.data / "db"
        self.procs = []              # [(name, Popen, stop_file)] in start order
        self.public_keys = {}

    # ------------------------------------------------------------- addressing
    def bind(self, section):
        return section["host"], int(section["port"])

    def url(self, section):
        host = section.get("url_host", section["host"])
        return "http://%s:%d" % (host, int(section["port"]))

    def witness_url(self, name):
        return self.url(self.cfg["witnesses"][name])

    @property
    def app_url(self):
        return self.url(self.cfg["app"])

    @property
    def gateway_url(self):
        return self.url(self.cfg["gateway"])

    @property
    def outside_url(self):
        return self.url(self.cfg["outside"])

    @property
    def stack_stop_file(self):
        return self.run_dir / "stack.stop"

    # ------------------------------------------------------------------- keys
    def _prepare_keys(self):
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        for name in WITNESS_NAMES:
            path = self.keys_dir / (name + ".seed")
            if path.exists():
                self.public_keys[name] = load_signing_key(path).verify_key.encode().hex()
            else:
                self.public_keys[name] = write_new_key_file(path)

    # ------------------------------------------------------------------ start
    def _spawn(self, name, module_args, ready_url=None):
        stop_file = self.run_dir / (name + ".stop")
        if stop_file.exists():
            stop_file.unlink()
        log = open(self.logs_dir / (name + ".log"), "ab")
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        proc = subprocess.Popen([sys.executable, "-m", *module_args, "--stop-file", str(stop_file)],
                                cwd=str(PYTHON_DIR), stdout=log, stderr=subprocess.STDOUT, env=env)
        self.procs.append((name, proc, stop_file))
        return proc, ready_url

    def _wait_ready(self, name, proc, url, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("%s exited early (exit code %s); see %s" % (
                    name, proc.returncode, self.logs_dir / (name + ".log")))
            if url is None:
                time.sleep(2)
                return
            try:
                if requests.get(url, timeout=1).status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(0.2)
        raise RuntimeError("%s did not become ready in %ss" % (name, timeout))

    def start(self, timeout=60):
        for d in (self.keys_dir, self.logs_dir, self.run_dir, self.db_dir):
            d.mkdir(parents=True, exist_ok=True)
        if self.stack_stop_file.exists():
            self.stack_stop_file.unlink()
        self._prepare_keys()
        anchor = self.cfg.get("anchor", {})
        pending = []
        try:
            for name in WITNESS_NAMES:
                host, port = self.bind(self.cfg["witnesses"][name])
                args = ["witness", "--role", name, "--name", name, "--host", host, "--port", str(port),
                        "--key-file", str(self.keys_dir / (name + ".seed")),
                        "--db", str(self.db_dir / (name + ".witness.db")),
                        "--anchor-file", str(self.data / (name + ".anchors.jsonl")),
                        "--backend", anchor.get("backend", "fake"),
                        "--anchor-interval", str(anchor.get("interval_seconds", 30)),
                        "--receipt-grace", str(anchor.get("receipt_grace_seconds", 10)),
                        "--batch-interval", str(self.cfg.get("batch_interval_seconds", 2))]
                if self.cfg.get("policy_file"):
                    args += ["--policy-file", str(self.cfg["policy_file"])]
                if anchor.get("backend") == "chain":
                    args += ["--confirmations", str(anchor.get("confirmations", 3))]
                    if anchor.get("deployment_file"):
                        args += ["--deployment-file", str(anchor["deployment_file"])]
                for other in WITNESS_NAMES:
                    if other != name:
                        args += ["--peer", "%s=%s=%s" % (other, self.witness_url(other), self.public_keys[other])]
                pending.append((name,) + self._spawn("witness_" + name, args, self.witness_url(name) + "/status"))
            for name, proc, url in pending:
                self._wait_ready(name, proc, url, timeout)

            out = self.cfg["outside"]
            if out.get("mode", "sink") == "sink":
                host, port = self.bind(out)
                args = ["outside", "--mode", "sink", "--host", host, "--port", str(port),
                        "--witness-url", self.witness_url("outside"), "--label", self.label]
                ready = self.outside_url + "/__stats"
            else:
                args = ["outside", "--mode", "scapy", "--iface", out["iface"], "--witness-url", self.witness_url("outside"),
                        "--label", self.label] + sum((["--watch-port", str(p)] for p in out["watch_ports"]), [])
                ready = None
            proc, _ = self._spawn("outside_capture", args, ready)
            self._wait_ready("outside_capture", proc, ready, timeout)

            host, port = self.bind(self.cfg["gateway"])
            proc, _ = self._spawn("gateway", ["gateway", "--host", host, "--port", str(port),
                                              "--witness-url", self.witness_url("network"), "--label", self.label],
                                  self.gateway_url + "/status")
            self._wait_ready("gateway", proc, self.gateway_url + "/status", timeout)

            app = self.cfg["app"]
            host, port = self.bind(app)
            proc, _ = self._spawn("demo_app", [
                "demo_app", "--host", host, "--port", str(port), "--db", str(self.db_dir / "quickpay.db"),
                "--witness-url", self.witness_url("app"), "--gateway-url", self.gateway_url,
                "--demo-password", app["demo_password"], "--customers", str(app.get("customers", 200)),
                "--label", self.label], self.app_url + "/status")
            self._wait_ready("demo_app", proc, self.app_url + "/status", timeout)
        except Exception:
            self.stop()
            raise
        return self

    # ------------------------------------------------------------------- stop
    def _witness_alive(self, name):
        return any(n == "witness_" + name and p.poll() is None for n, p, _ in self.procs)

    def flush_all(self, timeout=60):
        """A final exchange on every running witness, one after the other. Returns {witness: answer or error}."""
        out = {}
        for name in WITNESS_NAMES:
            if self._witness_alive(name):
                try:
                    out[name] = requests.post(self.witness_url(name) + "/flush", timeout=timeout).json()
                except (requests.RequestException, ValueError) as err:
                    out[name] = {"error": type(err).__name__}
        return out

    def prepare_shutdown_all(self, timeout=60):
        """Each witness in turn: flush, write its signed shutdown marker, flush again. All web servers are
        still up while this runs, so every witness can hear every other one."""
        out = {}
        for name in WITNESS_NAMES:
            if self._witness_alive(name):
                try:
                    out[name] = requests.post(self.witness_url(name) + "/prepare-shutdown", timeout=timeout).json()
                except (requests.RequestException, ValueError) as err:
                    out[name] = {"error": type(err).__name__}
        return out

    def export_bundles(self, out_dir, flush=True):
        """Write one evidence bundle per witness into out_dir. Running witnesses are flushed first (ALL of them,
        before any export). Returns {witness: path}."""
        from witness.export import write_bundle
        out_dir = Path(out_dir)
        if flush:
            self.flush_all()
        paths = {}
        for name in WITNESS_NAMES:
            paths[name] = out_dir / (name + ".bundle.json")
            write_bundle(self.db_path(name), paths[name])
        return paths

    def _stop_one(self, name, proc, stop_file, wait, outcome):
        if proc.poll() is None:
            stop_file.write_text("stop")
            try:
                proc.wait(timeout=wait)
                outcome[name] = "clean"
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
                outcome[name] = "killed"
        else:
            outcome[name] = "clean" if proc.returncode == 0 else "exited(%s)" % proc.returncode

    def stop(self, wait=25):
        """Clean stop. 1) the clients (app, outside capture, gateway) stop, so their last entries reach the
        witnesses; 2) every witness flushes, writes its shutdown marker and flushes again while all three are
        still serving; 3) only then the witnesses are told to exit. Returns {service: "clean" | "killed"}."""
        outcome = {}
        for name, proc, stop_file in [p for p in reversed(self.procs) if not p[0].startswith("witness_")]:
            self._stop_one(name, proc, stop_file, wait, outcome)
        self.prepare_shutdown_all()
        for name, proc, stop_file in [p for p in self.procs if p[0].startswith("witness_")]:
            self._stop_one(name, proc, stop_file, wait, outcome)
        self.procs = []
        return outcome

    def kill_service(self, name):
        """Hard-stop one service (used by tests to simulate it going down)."""
        for n, proc, _ in self.procs:
            if n == name and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)

    def db_path(self, witness_name):
        return self.db_dir / (witness_name + ".witness.db")
