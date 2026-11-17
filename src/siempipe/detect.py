"""Streaming detection engine for a practical subset of Sigma.

The same rule files are (a) executed here, in-stream, so detections can be
unit-tested and run without a SIEM, and (b) converted with pySigma into native
SIEM queries (Splunk SPL, Elastic Lucene) by ``siempipe convert``.

Supported Sigma features
------------------------
* Detection selections: maps (AND) and lists of maps (OR); value lists (OR)
* Modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, ``cidr``,
  ``all``, ``gt``, ``gte``, ``lt``, ``lte``; ``null`` = field absent
* Plain values match case-insensitively with ``*``/``?`` wildcards
* Conditions: ``and``, ``or``, ``not``, parentheses, ``1 of x*``,
  ``all of x*``, ``1 of them``, ``all of them``
* Correlation rules (Sigma v2) of ``type: event_count`` with ``group-by``,
  ``timespan`` and ``condition`` (gt/gte/lt/lte/eq) – evaluated when the
  threshold is reached, then the group is reset (one alert per burst).

Correlation state is kept in memory; it is not persisted across restarts.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import ipaddress
import re
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .schema import event_time, get_field, iso

LEVEL_SEVERITY = {"informational": 1, "low": 21, "medium": 47, "high": 73, "critical": 99}
_NUMERIC = {"gt", "gte", "lt", "lte"}
_SUPPORTED_MODS = {"contains", "startswith", "endswith", "re", "cidr", "all"} | _NUMERIC


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------------- values


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _wildcard(pattern: str) -> re.Pattern:
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE | re.DOTALL)


def _match_one(value: Any, expected: Any, mods: list[str]) -> bool:
    if expected is None:
        return value is None
    if value is None:
        return False
    if isinstance(value, (list, tuple, set)):
        return any(_match_one(v, expected, mods) for v in value)

    numeric = _NUMERIC.intersection(mods)
    if numeric:
        try:
            left, right = float(value), float(expected)
        except (TypeError, ValueError):
            return False
        op = numeric.pop()
        return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[op]

    if isinstance(expected, bool) or isinstance(value, bool):
        return _as_text(value).lower() == _as_text(expected).lower()

    text, pattern = _as_text(value), _as_text(expected)
    if "re" in mods:
        return re.search(pattern, text) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(text) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    if "contains" in mods:
        pattern = f"*{pattern}*"
    elif "startswith" in mods:
        pattern = f"{pattern}*"
    elif "endswith" in mods:
        pattern = f"*{pattern}"
    return _wildcard(pattern).match(text) is not None


def _match_field(event: dict, key: str, expected: Any) -> bool:
    name, *mods = key.split("|")
    unknown = set(mods) - _SUPPORTED_MODS
    if unknown:
        raise RuleError(f"unsupported modifier(s) {sorted(unknown)} on field {name!r}")
    value = get_field(event, name)
    options = expected if isinstance(expected, list) else [expected]
    if "all" in mods:
        return all(_match_one(value, e, mods) for e in options)
    return any(_match_one(value, e, mods) for e in options)


def _compile_selection(sel: Any) -> Callable[[dict], bool]:
    if isinstance(sel, dict):
        items = list(sel.items())
        for key, _ in items:  # validate modifiers at load time
            _match_field({}, key, None)
        return lambda ev: all(_match_field(ev, k, v) for k, v in items)
    if isinstance(sel, list) and all(isinstance(s, dict) for s in sel):
        parts = [_compile_selection(s) for s in sel]
        return lambda ev: any(p(ev) for p in parts)
    raise RuleError("only field selections (maps or lists of maps) are supported, not keyword lists")


# --------------------------------------------------------------------------- conditions

_TOKEN = re.compile(r"\s*(\(|\)|(?:1|all|any) of [\w*]+|\w[\w*]*|\S)")


def _compile_condition(condition: str, selections: dict[str, Callable]) -> Callable[[dict], bool]:
    tokens = _TOKEN.findall(condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise RuleError(f"unexpected end of condition: {condition!r}")
        tok = tokens[pos]
        pos += 1
        return tok

    def names(pattern: str) -> list[Callable]:
        found = [fn for n, fn in selections.items() if pattern == "them" or fnmatch.fnmatchcase(n, pattern)]
        if not found:
            raise RuleError(f"condition references no selection: {pattern!r}")
        return found

    def factor() -> Callable:
        tok = take()
        if tok.lower() == "not":
            inner = factor()
            return lambda ev: not inner(ev)
        if tok == "(":
            inner = expr()
            if take() != ")":
                raise RuleError(f"missing ')' in condition: {condition!r}")
            return inner
        quant = re.fullmatch(r"(1|all|any) of ([\w*]+)", tok)
        if quant:
            fns = names(quant[2])
            if quant[1] == "all":
                return lambda ev: all(f(ev) for f in fns)
            return lambda ev: any(f(ev) for f in fns)
        if tok not in selections:
            raise RuleError(f"unknown selection {tok!r} in condition")
        return selections[tok]

    def term() -> Callable:
        left = factor()
        while (peek() or "").lower() == "and":
            take()
            right, prev = factor(), left
            left = lambda ev, a=prev, b=right: a(ev) and b(ev)  # noqa: E731
        return left

    def expr() -> Callable:
        left = term()
        while (peek() or "").lower() == "or":
            take()
            right, prev = term(), left
            left = lambda ev, a=prev, b=right: a(ev) or b(ev)  # noqa: E731
        return left

    result = expr()
    if peek() is not None:
        raise RuleError(f"unexpected token {peek()!r} in condition: {condition!r}")
    return result


# --------------------------------------------------------------------------- rules


def _timespan(value: str) -> dt.timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", str(value).strip())
    if not m:
        raise RuleError(f"invalid timespan {value!r}")
    unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m[2]]
    return dt.timedelta(**{unit: int(m[1])})


@dataclass
class Rule:
    id: str
    title: str
    level: str
    name: str | None = None
    description: str = ""
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    matcher: Callable[[dict], bool] = lambda ev: False
    generate: bool = True
    source: str = ""


@dataclass
class Correlation:
    id: str
    title: str
    level: str
    rules: list[str]
    group_by: list[str]
    timespan: dt.timedelta
    op: str
    threshold: int
    name: str | None = None
    description: str = ""
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    generate: bool = False
    source: str = ""

    def satisfied(self, count: int) -> bool:
        return {
            "gt": count > self.threshold,
            "gte": count >= self.threshold,
            "eq": count == self.threshold,
            "lt": count < self.threshold,
            "lte": count <= self.threshold,
        }[self.op]


def _meta(doc: dict, source: str) -> dict:
    for key in ("id", "title", "level"):
        if not doc.get(key):
            raise RuleError(f"{source}: rule is missing {key!r}")
    if doc["level"] not in LEVEL_SEVERITY:
        raise RuleError(f"{source}: invalid level {doc['level']!r}")
    return {
        "id": str(doc["id"]),
        "title": doc["title"],
        "level": doc["level"],
        "name": doc.get("name"),
        "description": (doc.get("description") or "").strip(),
        "tags": list(doc.get("tags") or []),
        "falsepositives": list(doc.get("falsepositives") or []),
        "source": source,
    }


def parse_rule_document(doc: dict, source: str = "<memory>") -> Rule | Correlation:
    meta = _meta(doc, source)
    if "correlation" in doc:
        corr = doc["correlation"]
        if corr.get("type") != "event_count":
            raise RuleError(f"{source}: only event_count correlations are supported")
        cond = corr.get("condition") or {}
        if len(cond) != 1:
            raise RuleError(f"{source}: correlation condition needs exactly one operator")
        op, threshold = next(iter(cond.items()))
        if op not in {"gt", "gte", "eq", "lt", "lte"}:
            raise RuleError(f"{source}: invalid correlation operator {op!r}")
        group_by = corr.get("group-by") or []
        return Correlation(
            rules=[str(r) for r in corr.get("rules") or []],
            group_by=[group_by] if isinstance(group_by, str) else list(group_by),
            timespan=_timespan(corr.get("timespan", "")),
            op=op,
            threshold=int(threshold),
            generate=bool(corr.get("generate", False)),
            **meta,
        )
    detection = dict(doc.get("detection") or {})
    condition = detection.pop("condition", None)
    if not condition or not detection:
        raise RuleError(f"{source}: detection needs selections and a condition")
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    selections = {n: _compile_selection(s) for n, s in detection.items()}
    try:
        matcher = _compile_condition(str(condition), selections)
    except RuleError as exc:
        raise RuleError(f"{source}: {exc}") from exc
    return Rule(matcher=matcher, **meta)


def load_rules(paths: Iterable[Path]) -> list[Rule | Correlation]:
    loaded: list[Rule | Correlation] = []
    for path in paths:
        files = sorted(path.rglob("*.yml")) + sorted(path.rglob("*.yaml")) if path.is_dir() else [path]
        for file in files:
            for doc in yaml.safe_load_all(file.read_text(encoding="utf-8")):
                if doc:
                    loaded.append(parse_rule_document(doc, str(file)))
    return loaded


# --------------------------------------------------------------------------- engine


class Engine:
    """Feed events in time order with :meth:`process`; get back alert dicts."""

    def __init__(self, rules: list[Rule | Correlation], *, max_related: int = 10):
        self.rules = [r for r in rules if isinstance(r, Rule)]
        self.correlations = [c for c in rules if isinstance(c, Correlation)]
        self.max_related = max_related
        ids = [r.id for r in rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise RuleError(f"duplicate rule ids: {sorted(dupes)}")

        by_ref: dict[str, Rule] = {}
        for r in self.rules:
            by_ref[r.id] = r
            if r.name:
                by_ref[r.name] = r
        self._corr_by_rule: dict[str, list[Correlation]] = {}
        for c in self.correlations:
            for ref in c.rules:
                if ref not in by_ref:
                    raise RuleError(f"{c.source}: correlation references unknown rule {ref!r}")
                base = by_ref[ref]
                self._corr_by_rule.setdefault(base.id, []).append(c)
                if not c.generate:
                    base.generate = False
        self._state: dict[tuple[str, tuple], deque] = {}

    def process(self, event: dict) -> list[dict]:
        alerts: list[dict] = []
        for rule in self.rules:
            if not rule.matcher(event):
                continue
            if rule.generate:
                alerts.append(self._alert(rule, event, [event]))
            for corr in self._corr_by_rule.get(rule.id, []):
                alert = self._correlate(corr, event)
                if alert:
                    alerts.append(alert)
        return alerts

    def _correlate(self, corr: Correlation, event: dict) -> dict | None:
        group = tuple(_as_text(get_field(event, g, "")) for g in corr.group_by)
        window = self._state.setdefault((corr.id, group), deque())
        now = event_time(event)
        window.append((now, event))
        while window and now - window[0][0] > corr.timespan:
            window.popleft()
        if not corr.satisfied(len(window)):
            return None
        events = [e for _, e in window]
        window.clear()
        alert = self._alert(corr, event, events)
        alert["siempipe"]["correlation"] = {
            "count": len(events),
            "timespan_seconds": int(corr.timespan.total_seconds()),
            "group": dict(zip(corr.group_by, group, strict=True)),
            "first_seen": iso(event_time(events[0])),
        }
        return alert

    def _alert(self, rule: Rule | Correlation, trigger: dict, events: list[dict]) -> dict:
        alert: dict = {
            "@timestamp": trigger.get("@timestamp"),
            "event": {
                "kind": "alert",
                "module": "siempipe",
                "dataset": "siempipe.alert",
                "action": get_field(trigger, "event.action"),
                "severity": LEVEL_SEVERITY[rule.level],
            },
            "rule": {
                "id": rule.id,
                "name": rule.title,
                "description": rule.description,
                "ruleset": "siempipe",
                "category": "correlation" if isinstance(rule, Correlation) else "single-event",
            },
            "tags": rule.tags,
            "siempipe": {
                "level": rule.level,
                "falsepositives": rule.falsepositives,
                "related_events": [get_field(e, "event.original") or e for e in events[-self.max_related :]],
            },
        }
        for key in ("source", "user", "destination", "asset", "observer", "securoty"):
            if key in trigger:
                alert[key] = trigger[key]
        return alert
