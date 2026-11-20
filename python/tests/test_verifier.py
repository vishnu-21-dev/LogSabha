"""Step G1: evidence export + the offline verifier (integrity rules I1 to I7).

Most tests run on an in-memory ledger (fast). The last group runs against a REAL local Hardhat chain
through the chain helper. Every tampered case edits a COPY of a bundle or database; the live
witnesses are never touched. Only dummy fixed-seed keys appear here.
"""
import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from logsabha_core import ENTRY_FIELDS, GENESIS_PREV_HASH, sign_batch_header, sign_entry
from verifier.__main__ import main as verifier_main
from verifier.chain import HelperChainReader
from verifier.model import CANNOT, MATCH, MISMATCH, RULES
from verifier.report import human_report, json_report
from verifier.rules import verify
from witness.anchor import ChainAnchorBackend
from witness.core import PeerRejected
from witness.export import build_bundle

from test_chain_e2e import HELPER, chain_env, node_port, setup_local     # noqa: F401  (node_port is a fixture)
from test_witness import KEYS
from verifier_world import NAMES, PUB, SEEDS, World, copy_db, forged_entry, rebuild_from

PY_DIR = Path(__file__).resolve().parent.parent
BANNED = ("tamper-proof", "genuine", "fake", "hacked", "proves the truth", "court-approved")


# --------------------------------------------------------------------------- helpers
@pytest.fixture(scope="module")
def world(tmp_path_factory):
    return World(tmp_path_factory.mktemp("world"))


def write(bundles, folder):
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, b in bundles.items():
        p = folder / (name + ".json")
        p.write_text(json.dumps(b), encoding="utf-8")
        paths.append(str(p))
    return paths


def run(bundles, reader, tmp_path):
    return verify(write(bundles, tmp_path / "bundles"), reader)


def results(report, rule):
    return report.matrix()[rule]


def found(report, rule, witness, code=None, result=None):
    return [f for f in report.findings if f.rule == rule and f.subject == witness
            and (code is None or f.code == code) and (result is None or f.result == result)]


def fresh(world):
    return copy.deepcopy(world.bundles_cache)


@pytest.fixture(scope="module", autouse=True)
def _cache(world):
    world.bundles_cache = world.bundles()


# =================================================================== clean run
def test_clean_run_everything_matches_and_exits_zero(world, tmp_path):
    report = run(fresh(world), world.reader(), tmp_path)
    for rule in RULES:
        for w in NAMES:
            assert results(report, rule)[w] == MATCH, (rule, w, [f.statement for f in found(report, rule, w)])
    assert report.overall == MATCH and report.exit_code == 0
    assert any("restart marker" in n and "after_crash" in n and "App witness" in n for n in report.notices)   # listed
    assert any("not on the chain yet" in n for n in report.notices)                                           # the newest entries
    assert verifier_main(["verify", "--bundles", *write(fresh(world), tmp_path / "cli")], reader=world.reader()) == 0


# ========================================================================= I1
def test_one_edited_entry_is_an_I1_mismatch_at_the_exact_seq(world, tmp_path):
    b = fresh(world)
    entry = next(e for e in b["app"]["entries"] if e["seq"] == 7)
    entry["bytes"] += 1                                                   # content changed, hash left alone
    report = run(b, world.reader(), tmp_path)
    hit = found(report, "I1", "app", result=MISMATCH)
    assert [(f.code, f.seq_range) for f in hit] == [("hash", (7, 7))]
    assert results(report, "I1")["network"] == results(report, "I1")["outside"] == MATCH
    assert results(report, "I2")["app"] == MATCH                          # the signature covers the stored hash
    assert report.exit_code == 1


# ===================================================================== KEY CASE
def test_key_case_rebuilt_chain_passes_I1_and_I2_but_fails_I3_against_the_chain(world, tmp_path):
    copy_path = copy_db(world.db["app"], tmp_path / "app-copy.db")
    rebuild_from(copy_path, KEYS["app"], seq=8)                           # attacker with the key rewrites from seq 8
    attacked = build_bundle(copy_path)
    only_it = {"app": json.loads(json.dumps(attacked))}
    report = run(only_it, world.reader(), tmp_path)
    assert results(report, "I1")["app"] == MATCH                          # links and hashes: all consistent
    assert results(report, "I2")["app"] == MATCH                          # signatures: all made with the right key
    assert results(report, "I4")["app"] == MATCH
    hits = found(report, "I3", "app", result=MISMATCH)
    assert hits and all("entries" in f.code for f in hits)
    assert all(f.anchor_tx and f.anchor_tx.startswith("0x") for f in hits)
    assert report.exit_code == 1
    # with the other witnesses' bundles too, they also say "changed after we authenticated it"
    everyone = {**fresh(world), "app": json.loads(json.dumps(attacked))}
    report_all = run(everyone, world.reader(), tmp_path)
    assert found(report_all, "I5", "app", code="changed", result=MISMATCH)
    assert found(report_all, "I7", "app", code="two-headers", result=MISMATCH)   # it signed two versions of a batch


# ========================================================================= I5
def test_newest_entries_deleted_before_the_next_anchor_are_caught_by_peer_authenticators(world, tmp_path):
    b = fresh(world)
    last = b["outside"]["entries"][-1]["seq"]
    del b["outside"]["entries"][-2:]
    report = run(b, world.reader(), tmp_path)
    hit = found(report, "I5", "outside", code="deleted", result=MISMATCH)
    assert [f.seq_range for f in hit] == [(last, last)]          # peers hold an authenticator for the newest seq only
    assert {"App witness", "Network witness"} <= set(hit[0].to_dict()["witnesses"])
    assert not found(report, "I5", "outside", code="likely-forged")   # the remaining entry is not blamed as forged
    assert results(report, "I3")["outside"] == MATCH                       # the chain never saw these entries
    assert results(report, "I4")["outside"] == MATCH                       # a hole at the end is invisible to I4
    assert report.exit_code == 1


def test_an_entry_no_peer_authenticated_while_peers_were_answering_is_likely_forged(world, tmp_path):
    b = fresh(world)
    mid = b["network"]["entries"][10]
    entry = forged_entry(KEYS["network"], b["network"]["entries"][-1], mid["ts_utc"], "network")   # dated mid-run
    b["network"]["entries"].append(entry)
    report = run(b, world.reader(), tmp_path)
    hit = found(report, "I5", "network", code="likely-forged", result=MISMATCH)
    assert [f.seq_range for f in hit] == [(entry["seq"], entry["seq"])]
    for rule in ("I1", "I2", "I3", "I4"):
        assert results(report, rule)["network"] == MATCH, rule             # it looks perfectly consistent alone
    assert report.exit_code == 1


def test_if_no_peer_was_reachable_after_the_entry_it_is_cannot_verify_not_mismatch(world, tmp_path):
    b = fresh(world)
    entry = forged_entry(KEYS["network"], b["network"]["entries"][-1], "2999-01-01T00:00:00.000Z", "network")
    b["network"]["entries"].append(entry)
    report = run(b, world.reader(), tmp_path)
    assert found(report, "I5", "network", code="peers-unreachable", result=CANNOT)
    assert not found(report, "I5", "network", result=MISMATCH)
    assert report.overall == CANNOT and report.exit_code == 2


# ========================================================================= I2
def test_bad_signature_is_an_I2_mismatch(world, tmp_path):
    b = fresh(world)
    entry = next(e for e in b["app"]["entries"] if e["seq"] == 5)
    entry["sig"] = ("0" if entry["sig"][0] != "0" else "1") + entry["sig"][1:]
    report = run(b, world.reader(), tmp_path)
    assert [(f.code, f.seq_range) for f in found(report, "I2", "app", result=MISMATCH)] == [("entry", (5, 5))]
    assert results(report, "I1")["app"] == MATCH and results(report, "I3")["app"] == MATCH     # only I2 sees it
    assert report.exit_code == 1


def test_entry_signed_with_the_wrong_key_is_an_I2_mismatch(world, tmp_path):
    b = fresh(world)
    i = next(i for i, e in enumerate(b["app"]["entries"]) if e["seq"] == 5)
    body = {k: v for k, v in b["app"]["entries"][i].items() if k not in ("hash", "sig")}
    b["app"]["entries"][i] = sign_entry(KEYS["mallory"], body)           # same content and hash, different key
    report = run(b, world.reader(), tmp_path)
    assert [(f.code, f.seq_range) for f in found(report, "I2", "app", result=MISMATCH)] == [("entry", (5, 5))]
    assert results(report, "I1")["app"] == MATCH and results(report, "I3")["app"] == MATCH
    assert report.exit_code == 1


def test_a_different_key_registered_on_the_chain_fails_I2(world, tmp_path):
    other = {**PUB, "network": SigningKey(bytes([99]) * 32).verify_key.encode().hex()}
    report = run(fresh(world), world.reader(other), tmp_path)
    assert results(report, "I2")["network"] == MISMATCH
    assert found(report, "I2", "network", code="entry", result=MISMATCH)           # its own entries fail
    # the App witness's own entries still verify; only items signed BY the Network witness fail in its bundle
    assert not found(report, "I2", "app", code="entry")
    assert {f.code for f in found(report, "I2", "app", result=MISMATCH)} <= {"receipt-received", "authenticator", "peer-header"}
    assert report.exit_code == 1


def test_a_key_written_inside_a_bundle_is_never_used(world, tmp_path):
    b = fresh(world)
    b["app"]["public_key"] = SigningKey(bytes([99]) * 32).verify_key.encode().hex()
    b["app"]["signing_keys"] = {"app": b["app"]["public_key"]}
    assert run(b, world.reader(), tmp_path).exit_code == 0                  # ignored: the chain's key decides


@pytest.mark.parametrize("where,kind", [
    ("batches", "batch header"), ("receipts_issued", "receipt issued"), ("receipts_received", "receipt received"),
    ("authenticators", "authenticator"), ("peer_headers", "peer header")])
def test_bad_signatures_on_other_signed_items_are_I2_mismatches(world, tmp_path, where, kind):
    b = fresh(world)
    item = b["network"][where][0]
    target = item.get("header") or item.get("receipt") or item
    target["sig"] = ("0" if target["sig"][0] != "0" else "1") + target["sig"][1:]
    report = run(b, world.reader(), tmp_path)
    assert any(f.code == kind.replace(" ", "-") for f in found(report, "I2", "network", result=MISMATCH)), kind
    assert report.exit_code == 1


# ========================================================================= I4
def test_a_sequence_gap_without_a_restart_marker_is_a_mismatch(world, tmp_path):
    b = fresh(world)
    b["app"]["entries"] = [e for e in b["app"]["entries"] if e["seq"] not in (5, 6)]
    report = run(b, world.reader(), tmp_path)
    assert [(f.code, f.seq_range) for f in found(report, "I4", "app", result=MISMATCH)] == [("gap", (5, 6))]
    assert found(report, "I3", "app", result=MISMATCH)                      # the chain says those entries existed
    assert report.exit_code == 1


def chain_with_gap(key, marker):
    """Entries 1-4, then (a crash lost 5-7) an entry at seq 8: a signed restart marker, or an ordinary entry."""
    entries, prev = [], GENESIS_PREV_HASH
    for seq in (1, 2, 3, 4, 8, 9):
        kind = "restart" if (seq == 8 and marker) else "export"
        e = sign_entry(key, {"witness_id": "app", "boot_id": "boot-%d" % (1 if seq < 8 else 2), "seq": seq,
                             "ts_utc": "2026-11-20T02:00:%02d.000Z" % seq, "mono_ns": seq, "event_type": kind,
                             "request_id": None, "direction": "local", "dst": None, "bytes": 0,
                             "result": "after_crash" if kind == "restart" else "ok", "prev_hash": prev})
        entries.append(e)
        prev = e["hash"]
    return {"format": "logsabha-evidence-bundle", "version": 1, "witness_id": "app", "role": "app",
            "entries": entries, "markers": [], "batches": [], "windows": [], "receipts_issued": [],
            "receipts_received": [], "authenticators": [], "peer_headers": [], "conflicting_headers": []}


def test_a_gap_across_a_signed_restart_marker_is_allowed_and_listed(tmp_path):
    from verifier.chain import StaticChainReader
    reader = StaticChainReader({"app": PUB["app"]}, {"app": []})
    with_marker = verify(write({"app": chain_with_gap(KEYS["app"], True)}, tmp_path / "a"), reader)
    assert results(with_marker, "I4")["app"] == MATCH
    assert any("gap seq 5-7 is covered by the signed restart marker at seq 8" in n for n in with_marker.notices)
    assert any("restart marker at seq 8" in n for n in with_marker.notices)
    without = verify(write({"app": chain_with_gap(KEYS["app"], False)}, tmp_path / "b"), reader)
    assert [(f.code, f.seq_range) for f in found(without, "I4", "app", result=MISMATCH)] == [("gap", (5, 7))]
    # a restart marker signed with the WRONG key does not explain the gap
    forged_marker = verify(write({"app": chain_with_gap(KEYS["mallory"], True)}, tmp_path / "c"), reader)
    assert results(forged_marker, "I4")["app"] == MISMATCH


# ========================================================================= I6
def test_a_receipt_the_witness_issued_but_the_anchored_root_lacks_is_an_I6_mismatch(world, tmp_path):
    b = fresh(world)
    gone = b["app"]["receipts_issued"].pop(0)                                # app drops its first receipt
    held_by_peer = [r for r in b["network"]["receipts_received"] + b["outside"]["receipts_received"]
                    if r["receipt_hash"] == gone["receipt_hash"]]
    assert held_by_peer                                                      # a peer still holds the signed receipt
    report = run(b, world.reader(), tmp_path)
    hit = found(report, "I6", "app", code="missing-receipt", result=MISMATCH)
    assert hit and "not among the receipts" in hit[0].evidence[0]
    assert found(report, "I3", "app", result=MISMATCH)                       # the receipts root no longer matches either
    assert report.exit_code == 1


# ==================================================================== missing bundle
def test_no_bundle_for_one_witness_is_cannot_verify_and_exit_two(world, tmp_path):
    b = fresh(world)
    del b["outside"]
    report = run(b, world.reader(), tmp_path)
    for rule in RULES:
        assert results(report, rule)["outside"] == CANNOT, rule
        assert results(report, rule)["app"] == results(report, rule)["network"] == MATCH, rule
    assert not [f for f in report.findings if f.result == MISMATCH]
    assert report.overall == CANNOT and report.exit_code == 2
    assert verifier_main(["verify", "--bundles", *write(b, tmp_path / "cli")], reader=world.reader()) == 2


def test_unreadable_files_and_an_unreadable_chain_are_cannot_verify(world, tmp_path):
    good = write(fresh(world), tmp_path / "g")
    junk = tmp_path / "junk.json"
    junk.write_text("{not json", encoding="utf-8")
    report = verify(good + [str(junk)], world.reader())
    assert report.exit_code == 2 and report.bundle_notes
    class Broken(type(world.reader())):
        def witness_keys(self):
            from verifier.chain import ChainError
            raise ChainError("the chain cannot be reached")
    report = verify(good, Broken({}, {}))
    assert report.exit_code == 2 and not [f for f in report.findings if f.result == MISMATCH]
    assert report.chain_error


# ========================================================================= I7
def test_two_headers_for_one_batch_number_are_a_mismatch(tmp_path):
    w = World(tmp_path)
    network = w.ws["network"]
    first = network.store.get_peer_header("app", 3)
    body = {k: v for k, v in first.items() if k != "sig"}
    second = sign_batch_header(KEYS["app"], {**body, "entries_root": "ab" * 32})     # same batch number, other content
    assert second != first
    with pytest.raises(PeerRejected) as refused:
        network.handle_peer_header({"header": second, "authenticator": None})
    assert refused.value.code == 409                                                # still refused over HTTP
    assert network.store.count_conflicting_headers() == 1                           # and now kept in the database
    assert network.store.get_peer_header("app", 3) == first                         # the first one stays as it was
    assert network.status()["conflicting_headers"] == 1

    bundles = w.bundles()
    assert bundles["network"]["conflicting_headers"][0]["header"] == second
    report = run(bundles, w.reader(), tmp_path)
    hit = found(report, "I7", "app", code="two-headers", result=MISMATCH)
    assert len(hit) == 1 and "batch 3" in hit[0].statement
    assert results(report, "I7")["network"] == results(report, "I7")["outside"] == MATCH
    assert report.exit_code == 1


# ============================================================ export + bundle contents
def test_export_command_writes_a_bundle_without_keys_or_personal_data(world, tmp_path):
    copy_db(world.db["app"], tmp_path / "app.db")
    out = tmp_path / "out" / "bundle.json"
    proc = subprocess.run([sys.executable, "-m", "witness", "export", "--db", str(tmp_path / "app.db"), "--out", str(out)],
                          cwd=str(PY_DIR), capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["witness_id"] == "app" and bundle["entries"] and bundle["windows"] and bundle["authenticators"]
    assert all(set(e) == set(ENTRY_FIELDS) for e in bundle["entries"])              # only the logged fields
    assert {m["event_type"] for m in bundle["markers"]} <= {"restart", "shutdown"} and bundle["markers"]
    assert all(w["tx_hash"].startswith("0x") for w in bundle["windows"] if w["queue_state"] != "CREATED")
    text = out.read_text(encoding="utf-8").lower()
    for seed_hex in (("%02x" % b) * 32 for b in SEEDS.values()):
        assert seed_hex not in text                                                 # no private seed anywhere
    for word in ("seed", "private", "secret", "password", "key_file"):
        assert word not in text, word
    assert bundle["entries"] == world.bundles_cache["app"]["entries"]               # same content as the library export


# ================================================================ command line + wording
def test_finding_json_explain_and_exit_codes_on_the_command_line(world, tmp_path, capsys):
    b = fresh(world)
    next(e for e in b["app"]["entries"] if e["seq"] == 7)["bytes"] += 1
    paths = write(b, tmp_path / "cli")
    base = ["verify", "--bundles", *paths]

    assert verifier_main(base, reader=world.reader()) == 1
    text = capsys.readouterr().out
    assert "Overall: MISMATCH (exit code 1)" in text and "App witness" in text and "F-0001" not in text.split("Overall")[0]
    first_ids = re.findall(r"^(F-\d{4}) - ", text, re.M)
    assert first_ids

    assert verifier_main(base, reader=world.reader()) == 1                          # same inputs, same ids
    assert re.findall(r"^(F-\d{4}) - ", capsys.readouterr().out, re.M) == first_ids

    fid = first_ids[0]
    assert verifier_main(base + ["--finding", fid, "--explain"], reader=world.reader()) == 1
    one = capsys.readouterr().out
    for label in ("Result:", "Rule:", "Witnesses:", "Time range:", "Evidence:", "Limitation:", "Anchor tx:", "Answerable by:", "In plain words:"):
        assert label in one, label
    assert verifier_main(base + ["--finding", "F-9999"], reader=world.reader()) == 3
    capsys.readouterr()

    assert verifier_main(base + ["--json"], reader=world.reader()) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["overall"] == "MISMATCH" and data["exit_code"] == 1 and data["findings"]
    assert {"id", "result", "rule", "witnesses", "time_range", "evidence", "limitation", "anchor_tx", "answerable_by"} <= set(data["findings"][0])
    with pytest.raises(SystemExit) as usage:
        verifier_main(["verify"], reader=world.reader())                            # usage error is NOT exit code 2
    assert usage.value.code == 3
    capsys.readouterr()


def test_wording_rules_in_sources_reports_and_explanations(world, tmp_path):
    b = fresh(world)
    next(e for e in b["app"]["entries"] if e["seq"] == 7)["bytes"] += 1
    del b["outside"]["entries"][-2:]
    reports = []
    for bundles in (fresh(world), b):
        rep = run(bundles, world.reader(), tmp_path)
        reports += [human_report(rep, explain=True, show_all=True), json_report(rep)]
    sources = [p.read_text(encoding="utf-8") for p in (PY_DIR / "verifier").glob("*.py")]
    for text in reports + sources:
        low = text.lower()
        for word in BANNED:
            assert word not in low, word
    assert any("consistency evidence" in t.lower() for t in reports)
    assert all(name in " ".join(reports) for name in ("App witness", "Network witness", "Outside witness"))
    text = "\n".join(reports)
    assert "tamper-evident" in text.lower()


def test_the_verifier_never_talks_to_a_live_witness():
    for path in (PY_DIR / "verifier").glob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            assert not re.match(r"\s*(import|from)\s+(requests|socket|urllib|http|httpx|witness)\b", line), (path.name, line)


# =================================================================== the REAL local chain
@pytest.fixture(scope="module")
def real(node_port, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("real")
    dep = tmp / "deployment.json"
    env = chain_env(node_port, dep)
    keys, deployed = setup_local(env, SEEDS)
    world = World(tmp, backend_for=lambda n: ChainAnchorBackend(n, HELPER, deployment_file=dep, env=env),
                  windows=2, rounds_per_window=2)
    return {"world": world, "env": env, "dep": dep, "bundles": world.bundles(), "tmp": tmp}


def cli(real, paths, *extra):
    return subprocess.run([sys.executable, "-m", "verifier", "verify", "--bundles", *paths, "--chain-helper", HELPER,
                           "--deployment-file", str(real["dep"]), *extra],
                          cwd=str(PY_DIR), capture_output=True, text=True, timeout=300, env=real["env"])


def test_read_witness_returns_the_keys_registered_on_the_chain(real):
    keys = HelperChainReader(HELPER, deployment_file=real["dep"], env=real["env"]).witness_keys()
    assert set(keys) == set(NAMES)
    for name in NAMES:
        assert keys[name]["registered"] and keys[name]["active"] and keys[name]["public_key"] == PUB[name]
        assert len(keys[name]["public_key"]) == 64 and not keys[name]["public_key"].startswith("0x")


def test_real_chain_clean_run_exits_zero_from_the_command_line(real):
    proc = cli(real, write(copy.deepcopy(real["bundles"]), real["tmp"] / "clean"), "--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["overall"] == "MATCH" and all(v == "MATCH" for row in data["matrix"].values() for v in row.values())
    i3 = [f for f in data["findings"] if f["rule"] == "I3"]
    assert all(f["anchor_tx"].startswith("0x") for f in i3)


def test_real_chain_key_case_is_caught_only_by_the_chain(real, tmp_path):
    w = real["world"]
    copy_path = copy_db(w.db["outside"], tmp_path / "outside-copy.db")
    rebuild_from(copy_path, KEYS["outside"], seq=6)                       # the attacker holds the Outside witness's key
    attacked = json.loads(json.dumps(build_bundle(copy_path)))

    alone = write({"outside": attacked}, tmp_path / "alone")              # only the attacked bundle: the chain is all we have
    assert cli(real, alone).returncode == 1
    report = verify(alone, HelperChainReader(HELPER, deployment_file=real["dep"], env=real["env"]))
    assert results(report, "I1")["outside"] == MATCH and results(report, "I2")["outside"] == MATCH
    assert results(report, "I3")["outside"] == MISMATCH

    everyone = write({**copy.deepcopy(real["bundles"]), "outside": attacked}, tmp_path / "everyone")
    proc = cli(real, everyone)                                            # all three bundles supplied
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "I3" in proc.stdout and "MISMATCH" in proc.stdout
    print("\n----- SAMPLE REPORT: key case on the real local chain (all three bundles; the Outside witness copy was rebuilt with its own key) -----")
    print(proc.stdout)
