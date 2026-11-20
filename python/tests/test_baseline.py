"""Tests for the baseline's own verifier (B1 chain links, B2 anchored head), on a REAL local
chain: one Hardhat node for the whole file, the real chain helper, the real contract.
"""
import time

import pytest
from nacl.signing import SigningKey

from attacks.forge import delete_and_reseal
from baseline import BaselineLog, MATCH, MISMATCH, CANNOT, verify_baseline
from baseline.export import build_bundle
from verifier.chain import HelperChainReader

from test_chain_e2e import HELPER, chain_env, helper, node_port                 # noqa: F401 (node_port is a fixture)
from witness.anchor import ChainAnchorBackend

SEEDS = {"app": 21, "network": 22, "outside": 23, "baseline": 24}


@pytest.fixture
def chain(node_port, tmp_path):
    """One fresh deployment per test, with app/network/outside (unused) plus the baseline registered."""
    dep = tmp_path / "deployment.json"
    env = chain_env(node_port, dep)
    keys = {n: SigningKey(bytes([b]) * 32) for n, b in SEEDS.items() if n != "baseline"}
    out = helper(env, "setup-local", {"witnesses": {n: k.verify_key.encode().hex() for n, k in keys.items()},
                                      "maxGapSeconds": 600})
    assert out["ok"], out
    baseline_key = SigningKey(bytes([SEEDS["baseline"]]) * 32)
    reg = helper(env, "registerWitness", {"id": "baseline", "edPubKey": baseline_key.verify_key.encode().hex(),
                                          "maxGapSeconds": 600})
    assert reg["ok"], reg
    return env, dep, baseline_key


def make_baseline(tmp_path, env, dep, key, interval=600.0):
    backend = ChainAnchorBackend("baseline", HELPER, deployment_file=dep, env=env)
    return BaselineLog(key, "baseline", tmp_path / "baseline.db", backend)


def test_a_clean_log_matches_on_both_checks(chain, tmp_path):
    env, dep, key = chain
    b = make_baseline(tmp_path, env, dep, key)
    for i in range(3):
        b.add_entry("export", "r-%d" % i, "out", "127.0.0.1:9", 1000, "ok")
    header, tx = b.anchor_now()
    assert tx.startswith("0x")
    bundle = build_bundle(tmp_path / "baseline.db")
    reader = HelperChainReader(HELPER, deployment_file=dep, env=env)

    result = verify_baseline(bundle, reader)
    assert result["overall"] == MATCH
    assert {c["rule"]: c["result"] for c in result["checks"]} == {"B1": MATCH, "B2": MATCH}


def test_registering_twice_is_a_no_op(chain, tmp_path):
    env, dep, key = chain
    again = helper(env, "registerWitness", {"id": "baseline", "edPubKey": key.verify_key.encode().hex()})
    assert again["ok"] and again["alreadyRegistered"]


def test_before_anything_is_anchored_b2_is_cannot_verify(chain, tmp_path):
    env, dep, key = chain
    b = make_baseline(tmp_path, env, dep, key)
    b.add_entry("export", "r-1", "out", "127.0.0.1:9", 1000, "ok")
    bundle = build_bundle(tmp_path / "baseline.db")
    reader = HelperChainReader(HELPER, deployment_file=dep, env=env)

    result = verify_baseline(bundle, reader)
    by_rule = {c["rule"]: c for c in result["checks"]}
    assert by_rule["B1"]["result"] == MATCH                       # the chain itself is still fine
    assert by_rule["B2"]["result"] == CANNOT
    assert result["overall"] == CANNOT


def test_a_key_holder_who_deletes_and_reseals_still_matches_its_own_check(chain, tmp_path):
    """The exact limit this baseline is built to show: a single witness, holding its own key,
    can rewrite its own history before the next anchor, and B1 and B2 both still say MATCH."""
    env, dep, key = chain
    b = make_baseline(tmp_path, env, dep, key)
    for i in range(3):
        b.add_entry("export", "r-%d" % i, "out", "127.0.0.1:9", 1000, "ok")
    target = b._chain[1]["seq"]                 # drop the middle entry, BEFORE anchoring it
    b.store.close()

    delete_and_reseal(tmp_path / "baseline.db", key, [target])

    b2 = make_baseline(tmp_path, env, dep, key)        # reload: a fresh process picking up the tampered file
    b2.anchor_now()
    bundle = build_bundle(tmp_path / "baseline.db")
    reader = HelperChainReader(HELPER, deployment_file=dep, env=env)

    result = verify_baseline(bundle, reader)
    assert result["overall"] == MATCH                   # the baseline cannot tell: this is its stated limit
    assert {c["rule"]: c["result"] for c in result["checks"]} == {"B1": MATCH, "B2": MATCH}


def test_tampering_after_the_anchor_already_landed_is_a_b2_mismatch(chain, tmp_path):
    """The 'too slow' case: the true head was already put on the chain. Rewriting the local
    file afterwards cannot change what is already there, so B2 catches it."""
    env, dep, key = chain
    b = make_baseline(tmp_path, env, dep, key)
    for i in range(3):
        b.add_entry("export", "r-%d" % i, "out", "127.0.0.1:9", 1000, "ok")
    target = b._chain[1]["seq"]
    b.anchor_now()                                        # anchored BEFORE the tamper this time
    b.store.close()

    delete_and_reseal(tmp_path / "baseline.db", key, [target])

    bundle = build_bundle(tmp_path / "baseline.db")
    reader = HelperChainReader(HELPER, deployment_file=dep, env=env)
    result = verify_baseline(bundle, reader)
    by_rule = {c["rule"]: c for c in result["checks"]}
    assert by_rule["B1"]["result"] == MATCH                # its own chain is still internally consistent
    assert by_rule["B2"]["result"] == MISMATCH             # but it no longer matches what was already anchored
    assert result["overall"] == MISMATCH


def test_an_unregistered_witness_id_is_cannot_verify(chain, tmp_path):
    env, dep, key = chain
    bundle = {"witness_id": "nobody", "entries": [], "anchors": []}
    reader = HelperChainReader(HELPER, deployment_file=dep, env=env)
    result = verify_baseline(bundle, reader)
    assert result["overall"] == CANNOT
