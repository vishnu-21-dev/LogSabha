"""Quai-mode chain helper commands, run against a FAKE provider and a FAKE contract (see
quai_mock_harness.js). No network is reached and no real key exists anywhere in these tests: the
fake signers are just addresses. What is checked is the helper's own logic: which account sends
each transaction, one typed "yes" per transaction, the shard argument quais needs, parsing of
what the chain returns, and which file a deployment is saved to."""
import json
import os
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "quai_mock_harness.js")
REPO = os.path.dirname(os.path.dirname(HERE))


def run(scenario, tmp_path, stdin="", dry_run=False):
    env = dict(os.environ)
    env.pop("NETWORK", None)
    env["CHAIN_DEPLOYMENT_FILE"] = str(tmp_path / "deployment.json")
    art = tmp_path / "artifact.json"
    art.write_text(json.dumps({"abi": [], "bytecode": "0x"}))
    env["CHAIN_ARTIFACT"] = str(art)
    args = ["node", HARNESS, scenario] + (["--dry-run"] if dry_run else [])
    proc = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=60, env=env, cwd=REPO)
    assert proc.stdout.strip(), proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1]), proc.stderr


@pytest.fixture(scope="module")
def addr(tmp_path_factory):
    out, _ = run("addresses", tmp_path_factory.mktemp("a"))
    return out


def test_each_network_gets_its_own_deployment_file(tmp_path):
    out, _ = run("deployment_file_names", tmp_path)
    assert out["result"] == {"cyprus1": "deployment.cyprus1.json", "localhost": "deployment.localhost.json"}


def test_deploy_saves_the_contract_address_and_the_deploy_transaction_hash(tmp_path, addr):
    out, err = run("deploy", tmp_path, stdin="yes\n")
    res = out["result"]
    assert res["ok"] and res["registry"] == addr["registry"] and res["deployTxHash"].startswith("0x")
    saved = json.loads((tmp_path / "deployment.json").read_text())
    assert saved["registry"] == addr["registry"] and saved["deployTxHash"] == res["deployTxHash"]
    assert "new contract (its address is set when it is deployed)" in err  # no wrong predicted address
    assert [c["method"] for c in out["calls"]] == ["uploadMetadata", "deploy"]   # metadata first, after the yes
    assert out["calls"][1]["from"] == addr["deployer"] and out["calls"][1]["args"][1] == "ipfs:Qm" + "a" * 44
    assert saved["ipfsHash"] == "Qm" + "a" * 44


def test_deploy_dry_run_uploads_nothing_sends_nothing_and_writes_no_file(tmp_path):
    out, _ = run("deploy", tmp_path, dry_run=True)
    assert out["result"]["dryRun"] is True and out["calls"] == []     # no IPFS upload either
    assert not (tmp_path / "deployment.json").exists()


def test_deploy_stops_if_the_metadata_upload_gives_no_hash(tmp_path):
    out, _ = run("deploy_bad_hash", tmp_path, stdin="yes\n")
    assert "nothing was deployed" in out["error"]
    assert [c["method"] for c in out["calls"]] == ["uploadMetadata"]    # no deploy transaction
    assert not (tmp_path / "deployment.json").exists()


def test_deploy_without_the_yes_uploads_nothing(tmp_path):
    out, _ = run("deploy", tmp_path, stdin="no\n")
    assert "refused" in out["error"] and out["calls"] == []


def test_registering_a_witness_uses_that_roles_account_and_two_owners_each_with_a_prompt(tmp_path, addr):
    out, err = run("register_two_owners", tmp_path, stdin="yes\nyes\n")
    assert out["result"]["ok"] and out["result"]["alreadyRegistered"] is False
    assert [c["from"] for c in out["calls"]] == [addr["owner1"], addr["owner2"]]
    assert all(c["args"][1] == addr["app"] for c in out["calls"])          # the app role, not the deployer
    assert addr["deployer"] not in [c["args"][1] for c in out["calls"]]
    assert err.count('Type "yes"') == 2                                    # one prompt per transaction
    assert len(out["result"]["txs"]) == 2 and out["result"]["txs"][0]["gasUsed"]


def test_one_yes_sends_exactly_one_transaction(tmp_path, addr):
    out, _ = run("register_two_owners", tmp_path, stdin="yes\n")           # the second prompt hits end of input
    assert "refused" in out["error"]
    assert len(out["calls"]) == 1 and out["calls"][0]["from"] == addr["owner1"]


def test_a_wrong_answer_sends_nothing(tmp_path):
    out, _ = run("register_two_owners", tmp_path, stdin="no\n")
    assert "refused" in out["error"] and out["calls"] == []


def test_dry_run_shows_each_owner_transaction_with_its_own_sender_and_sends_nothing(tmp_path, addr):
    out, err = run("register_two_owners", tmp_path, dry_run=True)
    res = out["result"]
    assert res["dryRun"] is True and out["calls"] == []
    assert [s["sender"] for s in res["summaries"]] == [addr["owner1"], addr["owner2"]]
    assert all(s["contract"] == addr["registry"] and s["chainId"] == 15000 for s in res["summaries"])
    assert all(s["estimatedGas"] == "90000" for s in res["summaries"])
    assert err.count("About to register witness") == 2


def test_a_single_owner_approval_can_be_sent_on_its_own(tmp_path, addr):
    out, _ = run("register_step", tmp_path, stdin="yes\n")
    assert out["result"]["partial"] is True and out["result"]["step"] == 2 and out["result"]["txHash"]
    assert [c["from"] for c in out["calls"]] == [addr["owner2"]]


def test_registering_refuses_a_role_with_no_configured_account(tmp_path):
    out, _ = run("register_unconfigured_role", tmp_path, stdin="yes\nyes\n")
    assert "baseline" in out["error"] and out["calls"] == []


@pytest.mark.parametrize("scenario,word", [("register_witness_is_owner", "owner"), ("register_witness_is_deployer", "deployer")])
def test_registering_refuses_a_witness_account_that_is_an_owner_or_the_deployer(tmp_path, scenario, word):
    out, _ = run(scenario, tmp_path, stdin="yes\nyes\n")
    assert word in out["error"] and out["calls"] == []


def test_registering_needs_two_owner_keys(tmp_path):
    out, _ = run("register_one_owner_key", tmp_path, stdin="yes\nyes\n")
    assert "need 2 owner keys" in out["error"] and "CYPRUS1_OWNER" in out["error"] and out["calls"] == []


def test_an_anchor_is_sent_from_the_witnesses_own_account_after_its_own_yes(tmp_path, addr):
    out, err = run("register_then_anchor", tmp_path, stdin="yes\nyes\nyes\n")
    res = out["result"]
    assert res["ok"] and res["alreadyAnchored"] is False and res["txHash"].startswith("0x") and int(res["gasUsed"]) > 0
    assert out["calls"][-1]["method"] == "anchor" and out["calls"][-1]["from"] == addr["app"]


def test_an_anchor_without_a_yes_is_refused(tmp_path):
    out, _ = run("register_then_anchor", tmp_path, stdin="yes\nyes\n")     # no third yes
    assert "refused" in out["error"] and [c["method"] for c in out["calls"]] == ["registerWitness", "registerWitness"]


def test_reads_parse_what_the_chain_returns_and_pass_the_shard(tmp_path):
    out, _ = run("anchor_then_read", tmp_path, stdin="yes\nyes\nyes\n")
    res = out["result"]
    anchors = res["read"]["anchors"]
    assert [a["batchNo"] for a in anchors] == [1] and anchors[0]["gasUsed"] == "123456"
    assert anchors[0]["txHash"].startswith("0x") and anchors[0]["lastSeq"] == 5
    assert res["witness"]["witnesses"]["app"]["registered"] is True and res["witness"]["witnesses"]["app"]["active"] is True
    assert res["witness"]["witnesses"]["ghost"]["registered"] is False
    assert res["conf"]["confirmations"] >= 1                               # getBlockNumber got its shard argument
    assert res["events"]["latestBlockTime"] == 1700000005                  # time read from the quais block header


def test_admin_actions_prompt_per_transaction(tmp_path, addr):
    out, err = run("admin_pause", tmp_path, stdin="yes\nyes\nyes\nyes\n")
    pauses = [c for c in out["calls"] if c["method"] == "beginPause"]
    assert [c["from"] for c in pauses] == [addr["owner1"], addr["owner2"]]
    assert out["result"]["pauseUntil"] == 1700000005 + 60
    out, _ = run("admin_flag", tmp_path, stdin="yes\nyes\nyes\n")
    assert out["calls"][-1]["method"] == "flagSilence" and out["calls"][-1]["from"] == addr["deployer"]
