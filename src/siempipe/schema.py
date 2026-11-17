"""Helpers for the normalized event model.

Events are nested dicts following the Elastic Common Schema (ECS) field names
(``event.action``, ``source.ip``, ``user.id`` ...). Source-specific fields live
under their own namespace (e.g. ``securoty.*``). Detection rules address fields
with dotted paths, so lookups go through :func:`get_field`.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

_MISSING = object()


def get_field(event: dict, path: str, default: Any = None) -> Any:
    """Return the value at a dotted path, or ``default`` if any segment is missing.

    A literal key containing dots (``{"a.b": 1}``) is accepted as well, so flat
    events from other sources work too.
    """
    if path in event:
        return event[path]
    current: Any = event
    for part in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(part, _MISSING)
        if current is _MISSING:
            return default
    return current


def set_field(event: dict, path: str, value: Any) -> None:
    current = event
    *parents, leaf = path.split(".")
    for part in parents:
        current = current.setdefault(part, {})
    current[leaf] = value


def event_time(event: dict) -> dt.datetime:
    """Parse ``@timestamp`` (ISO 8601) into an aware datetime."""
    value = event.get("@timestamp")
    if isinstance(value, dt.datetime):
        return value
    if not value:
        return dt.datetime.now(dt.UTC)
    parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def iso(ts: dt.datetime) -> str:
    return ts.astimezone(dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
