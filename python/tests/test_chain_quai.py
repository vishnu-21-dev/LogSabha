"""Tests for Quai mode (NETWORK=cyprus1) in the chain helper: argument checks, address checks,
mainnet refusal, and dry-run output. NO network is ever reached by these tests: every case is
refused, or degrades gracefully, before any RPC call would be attempted. No command here ever
sends a transaction (Step Q1 is build-only).

Throw-away Cyprus-1 test keys are generated fresh inside this file (never printed, never
written anywhere outside a subprocess's own environment) and are worth nothing: there is no
funded account anywhere in this project.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLI = os.path.join(REPO, "chain", "cli.js")
QUAIS_DIR = os.path.join(REPO, "Solidity", "node_modules", "quais")

GRIND_SCRIPT = """
const q = require(process.argv[1]);
const crypto = require('crypto');
function grind() {
  for (let i = 0; i < 100000; i++) {
    const pk = '0x' + crypto.randomBytes(32).toString('hex');
    let addr;
    try { addr = q.computeAddress(pk); } catch (e) { continue; }
    if (q.getZoneForAddress(addr) === q.Zone.Cyprus1 && q.isQuaiAddress(addr)) return { pk, addr };
  }
  throw new Error('could not grind a Cyprus-1 address');
}
const n = Number(process.argv[2] || 1);
const out = [];
for (let i = 0; i < n; i++) out.push(grind());
process.stdout.write(JSON.stringify(out));
"""


def base_env(**overrides):
    env = dict(os.environ, NETWORK="cyprus1", CHAIN_ID="15000", RPC_URL="http://127.0.0.1:59999")
    # dotenv only fills in a variable that is MISSING from the environment, so deleting one here
    # would let the real .env's value leak straight back in. Setting it to "" instead means it is
    # present (dotenv leaves it alone) but still falsy everywhere this code checks for a key.
    for name in ("CYPRUS1_PK", "CYPRUS1_OWNER2_PK", "CYPRUS1_OWNER3_PK",
                 "CYPRUS1_APP_PK", "CYPRUS1_NETWORK_PK", "CYPRUS1_OUTSIDE_PK", "CYPRUS1_BASELINE_PK"):
        env[name] = ""
    env.update(overrides)
    return env


@pytest.fixture(scope="module")
def keypairs():
    """A handful of throw-away Cyprus-1, Quai-ledger (pk, address) pairs, ground offline. Never
    printed by the test runner: used only to populate subprocess environments programmatically."""
    proc = subprocess.run(["node", "-e", GRIND_SCRIPT, QUAIS_DIR, "6"], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def run_cli(*args, env=None, input_json=None, timeout=20):
    proc = subprocess.run(["node", CLI, *args], input=json.dumps(input_json) if input_json is not None else None,
                          capture_output=True, text=True, timeout=timeout, env=env, cwd=REPO)
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    return proc.returncode, out, proc.stderr


# ====================================================================== mode and chain id
def test_an_unsupported_network_name_is_refused():
    code, out, _ = run_cli("readWitness", env=base_env(NETWORK="somethingelse"))
    assert code == 1 and out["ok"] is False and "somethingelse" in out["error"]


def test_mainnet_chain_id_is_refused_for_every_command():
    for command in ("readWitness", "deploy", "anchor", "admin"):
        code, out, _ = run_cli(command, env=base_env(CHAIN_ID="9000"))
        assert code == 1 and out["ok"] is False
        assert "mainnet" in out["error"].lower() and "9000" in out["error"], (command, out)


def test_a_chain_id_that_is_neither_mainnet_nor_orchard_is_refused():
    code, out, _ = run_cli("readWitness", env=base_env(CHAIN_ID="31337"))
    assert code == 1 and out["ok"] is False and "15000" in out["error"]


def test_a_missing_chain_id_is_refused():
    code, out, _ = run_cli("readWitness", env=base_env(CHAIN_ID=""))        # "" stays, so dotenv cannot refill it
    assert code == 1 and out["ok"] is False and "CHAIN_ID" in out["error"]


def test_a_missing_rpc_url_is_refused():
    code, out, _ = run_cli("readWitness", env=base_env(RPC_URL=""))
    assert code == 1 and out["ok"] is False and "RPC_URL" in out["error"]


# ============================================================== keys are never printed
def test_a_malformed_private_key_gives_an_error_that_never_shows_its_value():
    bad_key = "0xNOT-A-REAL-KEY-AT-ALL-9f3e7b2c1a8d6f4e5c3b2a1908f7e6d5"
    code, out, _ = run_cli("readWitness", env=base_env(CYPRUS1_PK=bad_key))
    assert code == 1 and out["ok"] is False
    assert bad_key not in out["error"] and "NOT-A-REAL-KEY" not in out["error"]
    assert "CYPRUS1_PK" in out["error"]                     # names the env var, not the value


# ====================================================================== deploy: argument checks
def test_deploy_needs_exactly_three_owners(keypairs):
    env = base_env(CYPRUS1_PK=keypairs[0]["pk"])
    for owners in ([keypairs[1]["addr"]], [k["addr"] for k in keypairs[1:3]], [k["addr"] for k in keypairs[0:5]]):
        code, out, _ = run_cli("deploy", env=env, input_json={"owners": owners})
        assert code == 1 and out["ok"] is False and "exactly 3" in out["error"]


def test_deploy_needs_a_deployer_key_configured(keypairs):
    env = base_env()
    code, out, _ = run_cli("deploy", env=env, input_json={"owners": [k["addr"] for k in keypairs[1:4]]})
    assert code == 1 and out["ok"] is False and "CYPRUS1_PK" in out["error"]


# ====================================================================== deploy: address checks
def test_deploy_refuses_an_owner_that_is_not_a_valid_address(keypairs):
    env = base_env(CYPRUS1_PK=keypairs[0]["pk"])
    owners = [keypairs[1]["addr"], keypairs[2]["addr"], "0xnot-an-address"]
    code, out, _ = run_cli("deploy", env=env, input_json={"owners": owners})
    assert code == 1 and out["ok"] is False and "not a valid address" in out["error"]


def test_deploy_refuses_an_owner_that_is_not_a_cyprus1_address(keypairs):
    # Cyprus2's zone byte is 0x01: flip Cyprus1's leading byte to build an address that is a
    # valid, checksummed, Quai-ledger address but in the WRONG zone.
    import re

    def to_cyprus2(addr):
        return "0x01" + addr[4:]

    env = base_env(CYPRUS1_PK=keypairs[0]["pk"])
    wrong_zone = to_cyprus2(keypairs[1]["addr"])
    owners = [wrong_zone, keypairs[2]["addr"], keypairs[3]["addr"]]
    code, out, _ = run_cli("deploy", env=env, input_json={"owners": owners})
    assert code == 1 and out["ok"] is False
    assert "not a Cyprus-1 address" in out["error"] or "not a valid address" in out["error"], out


def test_deploy_refuses_duplicate_owner_addresses(keypairs):
    env = base_env(CYPRUS1_PK=keypairs[0]["pk"])
    owners = [keypairs[1]["addr"], keypairs[1]["addr"], keypairs[2]["addr"]]
    code, out, _ = run_cli("deploy", env=env, input_json={"owners": owners})
    assert code == 1 and out["ok"] is False and "all be different" in out["error"]


def test_deploy_refuses_an_owner_that_equals_the_deployer(keypairs):
    env = base_env(CYPRUS1_PK=keypairs[0]["pk"])
    owners = [keypairs[0]["addr"], keypairs[1]["addr"], keypairs[2]["addr"]]       # owner 1 == deployer
    code, out, _ = run_cli("deploy", env=env, input_json={"owners": owners})
    assert code == 1 and out["ok"] is False and "deployer" in out["error"]


def test_deploy_refuses_an_owner_that_equals_a_witness_account(keypairs):
    env = base_env(CYPRUS1_PK=keypairs[0]["pk"], CYPRUS1_APP_PK=keypairs[1]["pk"])
    owners = [keypairs[1]["addr"], keypairs[2]["addr"], keypairs[3]["addr"]]       # owner 1 == app witness
    code, out, _ = run_cli("deploy", env=env, input_json={"owners": owners})
    assert code == 1 and out["ok"] is False and "app" in out["error"]


# ====================================================================== dry-run
def test_dry_run_prints_a_summary_and_sends_nothing_even_with_no_reachable_chain(keypairs):
    env = base_env(CYPRUS1_PK=keypairs[0]["pk"])
    owners = [keypairs[1]["addr"], keypairs[2]["addr"], keypairs[3]["addr"]]
    code, out, err = run_cli("deploy", "--dry-run", env=env, input_json={"owners": owners}, timeout=30)
    assert code == 0 and out["ok"] is True and out["dryRun"] is True
    summary = out["summary"]
    assert summary["network"] == "Quai Orchard testnet (Cyprus-1)"
    assert summary["chainId"] == 15000
    assert summary["sender"].lower() == keypairs[0]["addr"].lower()
    assert "contract" in summary and "estimatedGas" in summary
    assert "unavailable" in summary["estimatedGas"]          # the RPC at 127.0.0.1:59999 cannot be reached
    assert "About to deploy" in err                          # the human-readable summary went to stderr


def test_dry_run_flag_is_accepted_in_any_position(keypairs):
    env = base_env(CYPRUS1_PK=keypairs[0]["pk"])
    owners = [keypairs[1]["addr"], keypairs[2]["addr"], keypairs[3]["addr"]]
    code, out, _ = run_cli("--dry-run", "deploy", env=env, input_json={"owners": owners}, timeout=30)
    assert code == 0 and out["ok"] is True and out["dryRun"] is True


def test_dry_run_still_enforces_address_checks_first(keypairs):
    env = base_env(CYPRUS1_PK=keypairs[0]["pk"])
    owners = [keypairs[0]["addr"], keypairs[1]["addr"], keypairs[2]["addr"]]       # owner 1 == deployer
    code, out, _ = run_cli("deploy", "--dry-run", env=env, input_json={"owners": owners})
    assert code == 1 and out["ok"] is False and "deployer" in out["error"]        # refused before any dry-run output


# ================================================================= help text
def test_the_help_text_lists_deploy_alongside_the_existing_commands():
    # cyprus1 mode needs no reachable RPC to get this far: connect() only checks the env vars.
    code, out, _ = run_cli("not-a-real-command", env=base_env())
    assert code == 1 and "deploy" in out["error"] and "setup-local" in out["error"] and "registerWitness" in out["error"]
