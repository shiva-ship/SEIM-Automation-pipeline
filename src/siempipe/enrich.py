"""Context enrichment: asset inventory and maintenance windows.

Alerts without context cannot be triaged (or safely automated), so every event
is enriched before detection:

* ``asset.*`` – zone, criticality and owner from a small YAML inventory, matched
  by SecurOTy agent name or by IP address.
* ``securoty.in_maintenance_window`` – for update/firmware actions, whether the
  event happened inside an approved maintenance window.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

from .schema import event_time, get_field, set_field

_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_WINDOW_ACTIONS = ("update.", "firmware.released", "agent.deploy")


@dataclass(frozen=True)
class MaintenanceWindow:
    days: frozenset[int]
    start: dt.time
    end: dt.time
    tz: ZoneInfo

    @classmethod
    def from_config(cls, raw: dict) -> MaintenanceWindow:
        days = raw.get("days", _DAYS)
        return cls(
            days=frozenset(_DAYS.index(str(d).lower()[:3]) for d in days),
            start=dt.time.fromisoformat(str(raw["start"])),
            end=dt.time.fromisoformat(str(raw["end"])),
            tz=ZoneInfo(raw.get("timezone", "UTC")),
        )

    def contains(self, ts: dt.datetime) -> bool:
        local = ts.astimezone(self.tz)
        t = local.time()
        if self.start <= self.end:
            return local.weekday() in self.days and self.start <= t < self.end
        # Window crosses midnight: the day refers to the start of the window.
        if t >= self.start:
            return local.weekday() in self.days
        return (local.weekday() - 1) % 7 in self.days and t < self.end


class Enricher:
    def __init__(self, assets: dict | None = None, windows: list[MaintenanceWindow] | None = None):
        assets = assets or {}
        self.by_agent: dict[str, dict] = assets.get("agents") or {}
        self.by_ip: dict[str, dict] = {str(k): v for k, v in (assets.get("hosts") or {}).items()}
        self.windows = windows or []

    @classmethod
    def from_config(cls, cfg: dict | None, base: Path) -> Enricher:
        cfg = cfg or {}
        assets = {}
        if cfg.get("assets"):
            path = (base / cfg["assets"]).resolve()
            assets = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        windows = [MaintenanceWindow.from_config(w) for w in cfg.get("maintenance_windows") or []]
        return cls(assets, windows)

    def enrich(self, event: dict) -> dict:
        asset = None
        agent = get_field(event, "securoty.agent")
        if agent is not None and str(agent) in self.by_agent:
            asset = {"name": str(agent), **self.by_agent[str(agent)]}
        else:
            for path in ("destination.address", "source.ip"):
                ip = get_field(event, path)
                if ip is not None and str(ip) in self.by_ip:
                    asset = {"ip": str(ip), **self.by_ip[str(ip)]}
                    break
        if asset:
            event["asset"] = asset

        action = str(get_field(event, "event.action", ""))
        if self.windows and action.startswith(_WINDOW_ACTIONS):
            ts = event_time(event)
            set_field(event, "securoty.in_maintenance_window", any(w.contains(ts) for w in self.windows))
        return event
