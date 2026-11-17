"""Output sinks: stdout, JSON-lines file, syslog (RFC 5424 over UDP/TCP/TLS) and HTTP.

Network sinks are wrapped in :class:`ReliableSink`, which spools undelivered
records to disk and retries them first on the next flush, so a SIEM outage
does not lose events. Secrets (HEC tokens, API keys) are read from environment
variables named in the config – never from the config file itself.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import sys
import time
import urllib.request
from pathlib import Path
from typing import Protocol

from .schema import event_time, get_field

log = logging.getLogger("siempipe.sinks")


class Sink(Protocol):
    def send(self, records: list[dict]) -> None: ...


def _dumps(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)


class StdoutSink:
    def __init__(self, stream=None):
        self.stream = stream or sys.stdout

    def send(self, records: list[dict]) -> None:
        for r in records:
            self.stream.write(_dumps(r) + "\n")
        self.stream.flush()


class FileSink:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def send(self, records: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            for r in records:
                fh.write(_dumps(r) + "\n")


# syslog severities: 2 crit, 3 err, 4 warning, 5 notice, 6 info
_LEVEL_TO_SYSLOG = {"critical": 2, "high": 3, "medium": 4, "low": 5, "informational": 6}


def _syslog_severity(record: dict) -> int:
    level = get_field(record, "siempipe.level")
    if level in _LEVEL_TO_SYSLOG:
        return _LEVEL_TO_SYSLOG[level]
    return 4 if get_field(record, "event.outcome") == "failure" else 6


def _printable(value: object, limit: int) -> str:
    text = "".join(c for c in str(value) if 33 <= ord(c) <= 126)
    return text[:limit] or "-"


def format_rfc5424(record: dict, *, app_name: str, hostname: str, facility: int) -> bytes:
    pri = facility * 8 + _syslog_severity(record)
    ts = event_time(record).isoformat(timespec="milliseconds")
    msgid = get_field(record, "rule.id") if get_field(record, "event.kind") == "alert" else None
    msgid = msgid or get_field(record, "event.action") or "-"
    header = (
        f"<{pri}>1 {ts} {_printable(hostname, 255)} {_printable(app_name, 48)} - {_printable(msgid, 32)} -"
    )
    # BOM marks the MSG part as UTF-8 per RFC 5424 section 6.4
    return header.encode("ascii") + b" \xef\xbb\xbf" + _dumps(record).encode("utf-8")


class SyslogSink:
    def __init__(
        self,
        host: str,
        port: int = 6514,
        protocol: str = "tls",
        *,
        ca_file: str | None = None,
        app_name: str = "siempipe",
        hostname: str | None = None,
        facility: int = 13,  # log audit
        timeout: float = 10.0,
    ):
        if protocol not in {"udp", "tcp", "tls"}:
            raise ValueError("syslog protocol must be udp, tcp or tls")
        self.host, self.port, self.protocol = host, int(port), protocol
        self.ca_file, self.app_name, self.facility, self.timeout = ca_file, app_name, int(facility), timeout
        self.hostname = hostname or socket.gethostname()

    def send(self, records: list[dict]) -> None:
        messages = [
            format_rfc5424(r, app_name=self.app_name, hostname=self.hostname, facility=self.facility)
            for r in records
        ]
        if self.protocol == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                for m in messages:
                    s.sendto(m, (self.host, self.port))
            return
        # RFC 6587 octet-counting framing for stream transports
        payload = b"".join(str(len(m)).encode() + b" " + m for m in messages)
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as raw:
            if self.protocol == "tls":
                ctx = ssl.create_default_context(cafile=self.ca_file)
                with ctx.wrap_socket(raw, server_hostname=self.host) as s:
                    s.sendall(payload)
            else:
                raw.sendall(payload)


class HttpSink:
    """POST batches to an HTTP collector.

    ``format``: ``ndjson`` (generic webhook / Logstash / Vector / Wazuh API
    proxies) or ``splunk_hec`` (Splunk HTTP Event Collector).
    """

    def __init__(
        self,
        url: str,
        format: str = "ndjson",
        *,
        token_env: str | None = None,
        auth_scheme: str = "Bearer",
        headers: dict | None = None,
        ca_file: str | None = None,
        timeout: float = 10.0,
        sourcetype: str = "_json",
        index: str | None = None,
    ):
        if format not in {"ndjson", "splunk_hec"}:
            raise ValueError("http format must be ndjson or splunk_hec")
        if not url.startswith("https://") and not url.startswith("http://localhost"):
            log.warning("HTTP sink %s is not using TLS", url)
        self.url, self.format, self.timeout = url, format, timeout
        self.headers = dict(headers or {})
        if token_env:
            token = os.environ.get(token_env)
            if not token:
                raise ValueError(f"environment variable {token_env} for HTTP sink token is not set")
            scheme = "Splunk" if format == "splunk_hec" and auth_scheme == "Bearer" else auth_scheme
            self.headers["Authorization"] = f"{scheme} {token}"
        self.context = ssl.create_default_context(cafile=ca_file) if url.startswith("https") else None
        self.sourcetype, self.index = sourcetype, index

    def _body(self, records: list[dict]) -> bytes:
        if self.format == "splunk_hec":
            out = []
            for r in records:
                item = {"time": event_time(r).timestamp(), "sourcetype": self.sourcetype, "event": r}
                item["source"] = get_field(r, "event.dataset") or "siempipe"
                if self.index:
                    item["index"] = self.index
                out.append(_dumps(item))
            return "".join(out).encode("utf-8")
        return ("\n".join(_dumps(r) for r in records) + "\n").encode("utf-8")

    def send(self, records: list[dict]) -> None:
        req = urllib.request.Request(self.url, data=self._body(records), method="POST")
        req.add_header("Content-Type", "application/x-ndjson" if self.format == "ndjson" else "application/json")
        for k, v in self.headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.context) as resp:
            if resp.status >= 300:
                raise OSError(f"HTTP sink returned {resp.status}")


class ReliableSink:
    """Disk-spooled retry wrapper: undelivered records survive outages and restarts."""

    def __init__(
        self,
        inner: Sink,
        spool: Path,
        *,
        batch_size: int = 500,
        max_spool_records: int = 100_000,
        retry_base: float = 2.0,
        retry_max: float = 300.0,
    ):
        self.inner, self.spool = inner, Path(spool)
        self.batch_size, self.max_spool_records = batch_size, max_spool_records
        self.retry_base, self.retry_max = retry_base, retry_max
        self._failures = 0
        self._next_try = 0.0

    def _spooled(self) -> list[dict]:
        if not self.spool.exists():
            return []
        out = []
        for line in self.spool.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def _write_spool(self, records: list[dict]) -> None:
        if len(records) > self.max_spool_records:
            dropped = len(records) - self.max_spool_records
            log.error("spool %s full: dropping %d oldest records", self.spool, dropped)
            records = records[dropped:]
        self.spool.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.spool.with_suffix(".tmp")
        tmp.write_text("".join(_dumps(r) + "\n" for r in records), encoding="utf-8")
        os.replace(tmp, self.spool)

    @property
    def pending(self) -> int:
        return len(self._spooled())

    def send(self, records: list[dict]) -> None:
        pending = self._spooled() + list(records)
        if not pending:
            return
        if time.monotonic() < self._next_try:
            self._write_spool(pending)
            return
        sent = 0
        try:
            for i in range(0, len(pending), self.batch_size):
                self.inner.send(pending[i : i + self.batch_size])
                sent = i + self.batch_size
        except Exception as exc:  # noqa: BLE001 - any delivery failure must spool, not crash
            self._failures += 1
            delay = min(self.retry_max, self.retry_base ** min(self._failures, 16))
            self._next_try = time.monotonic() + delay
            log.warning("delivery via %s failed (%s); spooled %d records, retry in %.0fs",
                        type(self.inner).__name__, exc, len(pending) - sent, delay)
            self._write_spool(pending[sent:])
            return
        self._failures = 0
        self._next_try = 0.0
        if self.spool.exists():
            self.spool.unlink()


def build_sink(cfg: dict, state_dir: Path, name: str) -> Sink:
    cfg = dict(cfg)
    kind = cfg.pop("type")
    reliable = cfg.pop("reliable", kind in {"syslog", "http"})
    if kind == "stdout":
        sink: Sink = StdoutSink()
    elif kind == "file":
        sink = FileSink(cfg["path"])
    elif kind == "syslog":
        sink = SyslogSink(**cfg)
    elif kind == "http":
        sink = HttpSink(**cfg)
    else:
        raise ValueError(f"unknown sink type {kind!r}")
    if reliable:
        sink = ReliableSink(sink, state_dir / f"{name}.spool.jsonl")
    return sink
