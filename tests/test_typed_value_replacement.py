"""Regression for precise typed immutable Value updates."""

from vulcscan.dataflow import Value, replace_value


def test_typed_value_replacement_preserves_taint_and_original() -> None:
    original = Value(dynamic=True, params=frozenset({0}), origin="request")
    updated = replace_value(original, dynamic=False, literal="checked")
    assert isinstance(updated, Value)
    assert updated.dynamic is False
    assert updated.literal == "checked"
    assert updated.params == frozenset({0})
    assert updated.origin == "request"
    assert original.dynamic is True
    assert not original.constant


def test_typed_value_replacement_can_clear_origin_without_losing_params() -> None:
    original = Value(params=frozenset({2}), origin="header")
    updated = replace_value(original, origin=None, sanitized=frozenset({"SQL_EXECUTION"}))
    assert updated.params == original.params
    assert updated.origin is None
    assert updated.sanitized == frozenset({"SQL_EXECUTION"})
