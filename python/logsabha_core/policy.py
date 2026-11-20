"""The policy file: the numbers the consistency rules read.

Its hash (SHA-256 of the canonical JSON of the normalised policy) goes into every anchor window
on the chain, so the verifier can tell whether the policy file it was given is the one that was
in force. Canonical JSON refuses floats, so every number here is a whole number.

Every value is a parameter. The numbers below are only the defaults used by the demo.
"""
import json

from .canonical import canonical_json
from .signing import sha256

DEFAULTS = {
    "egress_threshold_bytes": 10_000_000,      # demo: 10 MB
    "time_window_seconds": 5,                  # demo: records must be within 5 s of each other
    "byte_tolerance_percent": 5,               # demo: byte counts may differ by 5 %
    "cumulative_window_seconds": 300,          # 5 minutes
    "cumulative_threshold_bytes": 50_000_000,
}
INT_FIELDS = tuple(DEFAULTS)
FIELDS = ("version", "normal_destinations") + INT_FIELDS


class PolicyError(ValueError):
    pass


def normalize_destination(dst):
    """'Host:80' and 'host' are the same place. Lower case, port always present (default 80)."""
    text = str(dst).strip().lower()
    if not text:
        raise PolicyError("a destination cannot be empty")
    host, sep, port = text.rpartition(":")
    if sep and port.isdigit() and "]" not in port:
        return "%s:%d" % (host, int(port))
    return text + ":80"


def normalize_policy(obj):
    """Check a policy and return it in its one canonical form (defaults filled in, destinations sorted)."""
    if not isinstance(obj, dict):
        raise PolicyError("the policy must be a JSON object")
    unknown = sorted(set(obj) - set(FIELDS))
    if unknown:
        raise PolicyError("unknown policy field(s): " + ", ".join(unknown))
    version = obj.get("version")
    if not isinstance(version, str) or not version.strip():
        raise PolicyError("the policy needs a 'version' text (for example \"demo-1\")")
    dests = obj.get("normal_destinations")
    if not isinstance(dests, list) or not all(isinstance(d, str) for d in dests):
        raise PolicyError("'normal_destinations' must be a list of host:port texts")
    out = {"version": version.strip(), "normal_destinations": sorted({normalize_destination(d) for d in dests})}
    for name in INT_FIELDS:
        value = obj.get(name, DEFAULTS[name])
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise PolicyError("'%s' must be a whole number above 0" % name)
        out[name] = value
    return out


def policy_hash_hex(policy):
    return sha256(canonical_json(normalize_policy(policy))).hex()


def load_policy_file(path):
    """Returns (normalised policy, hash hex). Raises PolicyError with a plain reason."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except OSError:
        raise PolicyError("the policy file cannot be read")
    except ValueError:
        raise PolicyError("the policy file is not valid JSON")
    policy = normalize_policy(raw)
    return policy, policy_hash_hex(policy)


def write_policy_file(path, policy):
    policy = normalize_policy(policy)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2, sort_keys=True)
        f.write("\n")
    return policy_hash_hex(policy)
