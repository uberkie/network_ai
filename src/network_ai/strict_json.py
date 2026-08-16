"""Strict, bounded JSON decoding for untrusted local fixture bytes."""

from __future__ import annotations

from decimal import Decimal
import json
from typing import Any

from .contracts import ValidationError


MAX_NESTING = 32
MAX_OBJECT_MEMBERS = 512
MAX_ARRAY_ITEMS = 256


class _DuplicateKey(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValidationError("non_finite_number")


def _validate_bounds(value: Any, depth: int = 0) -> None:
    if depth > MAX_NESTING:
        raise ValidationError("json_nesting_exceeded")
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_MEMBERS:
            raise ValidationError("json_object_members_exceeded")
        for child in value.values():
            _validate_bounds(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_ARRAY_ITEMS:
            raise ValidationError("json_array_items_exceeded")
        for child in value:
            _validate_bounds(child, depth + 1)


def parse_strict_json(raw: bytes) -> dict[str, Any]:
    """Decode exactly one UTF-8 JSON object without permissive JSON extensions."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationError("invalid_utf8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=Decimal,
        )
    except _DuplicateKey as exc:
        raise ValidationError("duplicate_json_key") from exc
    except ValidationError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValidationError("invalid_json") from exc
    if not isinstance(parsed, dict):
        raise ValidationError("json_root_not_object")
    _validate_bounds(parsed)
    return parsed
