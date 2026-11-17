"""Wire sources -> parse -> enrich -> detect -> sinks from a YAML config."""

from __future__ import annotations

import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .detect import Engine, load_rules
from .enrich import Enricher
from .sinks import Sink, build_sink
from .sources import PARSERS
from .tail import FileFollower

log = logging.getLogger("siempipe")


@dataclass
class Source:
    name: str
    parser: str
    follower: FileFollower | None
    options: dict = field(default_factory=dict)

    def parse(self, line: str) -> dict | None:
        return PARSERS[self.parser](line, **self.options)


@dataclass
class Stats:
    lines: int = 0
    events: int = 0
    unparsed: int = 0
    alerts: Counter = field(default_factory=Counter)


class Pipeline:
    def __init__(
        self,
        enricher: Enricher,
        engine: Engine,
        event_sinks: list[Sink] | None = None,
        alert_sinks: list[Sink] | None = None,
        sources: list[Source] | None = None,
        poll_interval: float = 2.0,
    ):
        self.enricher, self.engine = enricher, engine
        self.event_sinks, self.alert_sinks = event_sinks or [], alert_sinks or []
        self.sources = sources or []
        self.poll_interval = poll_interval
        self.stats = Stats()

    @classmethod
    def from_config(cls, path: Path, *, with_outputs: bool = True) -> Pipeline:
        """Build from YAML. ``with_outputs=False`` skips sinks (replay/testing needs no SIEM credentials)."""
        path = Path(path).resolve()
        base = path.parent
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        state_dir = (base / cfg.get("state_dir", "state")).resolve()

        sources = []
        for i, src in enumerate(cfg.get("sources") or []):
            src = dict(src)
            name = src.pop("name", f"source{i}")
            kind = src.pop("type")
            if kind not in PARSERS:
                raise ValueError(f"unknown source type {kind!r}")
            follower = FileFollower(
                base / src.pop("path"),
                state_dir / f"{name}.checkpoint.json",
                start_at=src.pop("start_at", "beginning"),
            )
            sources.append(Source(name, kind, follower, src))

        det = cfg.get("detections") or {}
        rule_dirs = [base / p for p in det.get("rules", ["../detections/rules"])]
        engine = Engine(load_rules(rule_dirs))
        enricher = Enricher.from_config(cfg.get("enrichment"), base)

        outputs = (cfg.get("outputs") or {}) if with_outputs else {}
        event_sinks = [build_sink(s, state_dir, f"events{i}") for i, s in enumerate(outputs.get("events") or [])]
        alert_sinks = [build_sink(s, state_dir, f"alerts{i}") for i, s in enumerate(outputs.get("alerts") or [])]
        return cls(enricher, engine, event_sinks, alert_sinks, sources, float(cfg.get("poll_interval", 2.0)))

    def process(self, lines: list[str], source: Source) -> tuple[list[dict], list[dict]]:
        events, alerts = [], []
        for line in lines:
            self.stats.lines += 1
            event = source.parse(line)
            if event is None:
                self.stats.unparsed += 1
                log.debug("unparsed line from %s: %.120s", source.name, line)
                continue
            self.enricher.enrich(event)
            events.append(event)
            for alert in self.engine.process(event):
                self.stats.alerts[alert["rule"]["name"]] += 1
                alerts.append(alert)
        self.stats.events += len(events)
        return events, alerts

    def deliver(self, events: list[dict], alerts: list[dict]) -> None:
        for sink in self.event_sinks:
            if events:
                sink.send(events)
        for sink in self.alert_sinks:
            if alerts:
                sink.send(alerts)

    def poll_once(self) -> int:
        handled = 0
        for source in self.sources:
            assert source.follower is not None
            lines = source.follower.read()
            if lines:
                events, alerts = self.process(lines, source)
                self.deliver(events, alerts)
                handled += len(lines)
            source.follower.commit()
        return handled

    def run(self, *, once: bool = False) -> None:
        log.info("pipeline started: %d sources, %d rules, %d correlations", len(self.sources),
                 len(self.engine.rules), len(self.engine.correlations))
        while True:
            self.poll_once()
            if once:
                return
            time.sleep(self.poll_interval)
