"""Parser for the SecurOTy (firmware-updater-gruppe3) audit log.

SecurOTy writes ``backend/audit.py`` records as::

    2026-11-17 11:20:00,123 {"event": "auth.login_failed", "ip": "10.0.0.5"}

* The timestamp is the server's *local* time without a zone (Python logging
  ``asctime``), so the source timezone must be configured.
* Values are passed through ``_safe()``, which stringifies non-scalars with
  ``str()``. ``update.finished.summary`` (a dict) and
  ``assets.neighbors_new.macs`` (a list) therefore arrive as Python ``repr``
  strings and are decoded here with :func:`ast.literal_eval`.
* The audit log never contains secrets, so ``event.original`` is kept.
"""

from __future__ import annotations

import ast
import datetime as dt
import json
import re
from zoneinfo import ZoneInfo

from ..schema import iso, set_field

_LINE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (?P<msg>\{.*\})\s*$")

# action -> (event.category, event.type, default event.outcome)
ACTIONS: dict[str, tuple[list[str], list[str], str]] = {
    "server.start": (["process"], ["start"], "success"),
    "server.stop": (["process"], ["end"], "success"),
    "auth.login": (["authentication", "session"], ["start"], "success"),
    "auth.login_failed": (["authentication"], ["start"], "failure"),
    "keepass.uploaded": (["file"], ["creation"], "success"),
    "keepass.unlocked": (["authentication"], ["access"], "success"),
    "keepass.unlock_failed": (["authentication"], ["access"], "failure"),
    "firmware.released": (["package"], ["creation"], "success"),
    "firmware.revoked": (["package"], ["deletion"], "success"),
    "advisories.refreshed": (["vulnerability"], ["info"], "success"),
    "update.started": (["package"], ["installation", "start"], "unknown"),
    "update.finished": (["package"], ["installation", "end"], "unknown"),
    "agent.enrolled": (["iam"], ["creation"], "success"),
    "agent.revoked": (["iam"], ["deletion"], "success"),
    "agent.decommissioned": (["iam"], ["deletion"], "success"),
    "agent.auth_failed": (["authentication"], ["denied"], "failure"),
    "agent.assets_reported": (["host"], ["info"], "success"),
    "agent.tasks_created": (["configuration"], ["creation"], "success"),
    "agent.task_claimed": (["configuration"], ["access"], "success"),
    "agent.task_expired": (["configuration"], ["end"], "failure"),
    "agent.result": (["host"], ["info"], "unknown"),
    "agent.result_rejected": (["host"], ["denied"], "failure"),
    "agent.image_signed": (["package"], ["creation"], "success"),
    "agent.deploy_start": (["package"], ["installation", "start"], "unknown"),
    "agent.deployed": (["package"], ["installation"], "success"),
    "agent.deploy_failed": (["package"], ["installation"], "failure"),
    "assets.neighbors_new": (["network"], ["info"], "unknown"),
    "assets.cleared": (["configuration"], ["deletion"], "success"),
    "pki.initialized": (["configuration"], ["creation"], "success"),
    "agent_api.error": (["web"], ["error"], "failure"),
}

_REPR_FIELDS = {"summary", "macs"}


def _decode_repr(value):
    """Decode a Python-repr string written by SecurOTy; return the input unchanged on failure.

    Note: SecurOTy truncates values to 200 chars, so long lists may be cut and undecodable.
    """
    if not isinstance(value, str) or value[:1] not in ("{", "[", "("):
        return value
    try:
        return ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return value


def parse_securoty_line(line: str, *, timezone: str = "UTC", host: str | None = None) -> dict | None:
    """Turn one audit log line into an ECS event. Returns None for blank/unparseable lines."""
    line = line.rstrip("\r\n")
    match = _LINE.match(line)
    if not match:
        return None
    try:
        payload = json.loads(match["msg"])
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or "event" not in payload:
        return None

    local = dt.datetime.strptime(match["ts"], "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=ZoneInfo(timezone))
    action = str(payload.pop("event"))
    fields = {k: (_decode_repr(v) if k in _REPR_FIELDS else v) for k, v in payload.items()}
    category, types, outcome = ACTIONS.get(action, ([], ["info"], "unknown"))

    event: dict = {
        "@timestamp": iso(local),
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "event",
            "module": "securoty",
            "dataset": "securoty.audit",
            "action": action,
            "category": category,
            "type": types,
            "outcome": outcome,
            "original": line,
        },
        "observer": {"vendor": "Gruppe 3", "product": "SecurOTy", "type": "firmware-manager"},
        "securoty": fields,
    }
    if host:
        set_field(event, "observer.hostname", host)

    # Common ECS fields
    if "ip" in fields:
        set_field(event, "source.ip", fields["ip"])
    actor = fields.get("user_id", fields.get("by"))
    if actor is not None:
        set_field(event, "user.id", str(actor))
    if "host" in fields:
        set_field(event, "destination.address", fields["host"])
    if "error" in fields:
        set_field(event, "error.type", fields["error"])
    if "reason" in fields:
        set_field(event, "event.reason", fields["reason"])

    _derive(action, fields, event)
    return event


def _derive(action: str, fields: dict, event: dict) -> None:
    """Action-specific derived fields that detections can rely on."""
    if action == "update.finished":
        summary = fields.get("summary")
        if isinstance(summary, dict):
            bad = int(summary.get("failed", 0)) + int(summary.get("aborted", 0))
            set_field(event, "event.outcome", "failure" if bad else "success")
    elif action == "agent.result":
        overall = fields.get("overall")
        set_field(event, "event.outcome", "success" if overall == "ok" else "failure")
        mismatches = fields.get("mismatches")
        if isinstance(mismatches, str):
            fields["mismatches"] = [m for m in mismatches.split(",") if m]
    elif action == "assets.neighbors_new":
        macs = fields.get("macs")
        if isinstance(macs, list):
            fields["macs_count"] = len(macs)
