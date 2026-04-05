"""Small TOML writer shim.

Uses tomli-w when available and falls back to a minimal local serializer.
The fallback only supports the shapes vpnctl writes today: nested tables,
arrays of tables, primitive scalars, and lists of primitives.
"""

from __future__ import annotations

import json
import re
from typing import Any

try:
    import tomli_w as _tomli_w
except ImportError:  # pragma: no cover - fallback exercised instead
    _tomli_w = None

_BARE_KEY = re.compile(r"^[A-Za-z0-9_]+$")


def dumps(data: dict[str, Any]) -> str:
    if _tomli_w is not None:
        return _tomli_w.dumps(data)
    lines: list[str] = []
    _emit_table([], data, lines)
    return "\n".join(lines).rstrip() + "\n"


def _emit_table(path: list[str], table: dict[str, Any], lines: list[str]) -> None:
    scalar_items: list[tuple[str, Any]] = []
    dict_items: list[tuple[str, dict[str, Any]]] = []
    array_table_items: list[tuple[str, list[dict[str, Any]]]] = []

    for key, value in table.items():
        if isinstance(value, dict):
            dict_items.append((key, value))
        elif _is_array_of_tables(value):
            array_table_items.append((key, value))
        else:
            scalar_items.append((key, value))

    if path:
        lines.append(f"[{'.'.join(_format_key(part) for part in path)}]")

    for key, value in scalar_items:
        lines.append(f"{_format_key(key)} = {_format_value(value)}")

    if scalar_items and (dict_items or array_table_items):
        lines.append("")

    for idx, (key, value) in enumerate(dict_items):
        _emit_table(path + [key], value, lines)
        if idx != len(dict_items) - 1 or array_table_items:
            lines.append("")

    for key_index, (key, tables) in enumerate(array_table_items):
        for table_index, item in enumerate(tables):
            lines.append(f"[[{'.'.join(_format_key(part) for part in path + [key])}]]")
            for item_key, item_value in item.items():
                if isinstance(item_value, dict) or _is_array_of_tables(item_value):
                    raise TypeError("Nested tables inside arrays are not supported")
                lines.append(f"{_format_key(item_key)} = {_format_value(item_value)}")
            if table_index != len(tables) - 1:
                lines.append("")
        if key_index != len(array_table_items) - 1:
            lines.append("")


def _format_key(key: str) -> str:
    return key if _BARE_KEY.match(key) else json.dumps(key)


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_format_value(item) for item in value) + "]"
    raise TypeError(f"Unsupported TOML value: {value!r}")


def _is_array_of_tables(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, dict) for item in value)
