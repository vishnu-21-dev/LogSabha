import pytest
from nacl.signing import SigningKey

from logsabha_core import append_entry


@pytest.fixture
def sk():
    # Test-only key made from a fixed dummy seed. Not a real key.
    return SigningKey(bytes([1]) * 32)


@pytest.fixture
def vk(sk):
    return sk.verify_key


@pytest.fixture
def other_sk():
    return SigningKey(bytes([2]) * 32)


def entry_fields(i):
    return {
        "witness_id": "app",
        "boot_id": "boot-1",
        "ts_utc": "2026-11-20T02:%02d:00Z" % i,
        "mono_ns": 1_000_000 * i,
        "event_type": "export",
        "request_id": "req-%d" % i,
        "direction": "out",
        "dst": "203.0.113.58",
        "bytes": 100 * i,
        "result": "ok",
    }


@pytest.fixture
def make_chain():
    def _make(signing_key, n):
        chain = []
        for i in range(1, n + 1):
            append_entry(signing_key, chain, entry_fields(i))
        return chain
    return _make
