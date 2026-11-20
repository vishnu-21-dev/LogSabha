"""Canonical JSON: the same data always becomes the same bytes.

Rules: keys sorted, no extra spaces, UTF-8, no NaN or Infinity.
Floats are refused on purpose: 1.0 and 1 could be written differently by
different programs, and then hashes would not match. Use ints or strings.
"""
import json


def _check(obj):
    if obj is None or isinstance(obj, (bool, int, str)):
        return
    if isinstance(obj, float):
        raise ValueError("floats are not allowed in canonical JSON (use int or str)")
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON keys must be strings")
            _check(value)
        return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            _check(item)
        return
    raise TypeError("type not allowed in canonical JSON: " + type(obj).__name__)


def canonical_json(obj) -> bytes:
    """Return the canonical UTF-8 bytes of obj."""
    _check(obj)
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")
