import pytest

from logsabha_core import canonical_json


def test_reordered_keys_give_identical_bytes():
    a = {"b": 1, "a": {"y": [1, 2], "x": "hi"}, "c": None}
    b = {"c": None, "a": {"x": "hi", "y": [1, 2]}, "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_exact_format_no_spaces_sorted_utf8():
    out = canonical_json({"b": 2, "a": "é"})
    assert out == '{"a":"é","b":2}'.encode("utf-8")


def test_nan_and_floats_are_refused():
    for bad in (float("nan"), float("inf"), 1.5):
        with pytest.raises(ValueError):
            canonical_json({"x": bad})


def test_non_string_keys_and_odd_types_are_refused():
    with pytest.raises(TypeError):
        canonical_json({1: "a"})
    with pytest.raises(TypeError):
        canonical_json({"x": object()})
