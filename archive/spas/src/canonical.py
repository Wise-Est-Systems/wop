"""Canonical JSON serialization per SPAS §3 Law 3 and §15.3."""

from __future__ import annotations

import json
import math
from typing import Any


def _validate(obj: Any) -> None:
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise ValueError("canonical JSON forbids NaN and Infinity")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("canonical JSON requires string object keys")
            _validate(v)
        return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            _validate(item)
        return


def canonicalize(obj: Any) -> bytes:
    """Encode obj as canonical SPAS JSON (UTF-8 bytes).

    Rules: sorted keys, no insignificant whitespace, no NaN/Infinity,
    UTF-8, ensure_ascii=False so non-ASCII strings are emitted as raw UTF-8.
    """
    _validate(obj)
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")
