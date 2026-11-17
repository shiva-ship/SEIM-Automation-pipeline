import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from siempipe.sinks import FileSink, HttpSink, ReliableSink, SyslogSink, build_sink, format_rfc5424

EVENT = {"@timestamp": "2026-11-17T10:00:00.000Z", "event": {"action": "auth.login_failed", "outcome": "failure"}}
ALERT = {"@timestamp": "2026-11-17T10:00:00.000Z", "event": {"kind": "alert"}, "rule": {"id": "abc"},
         "siempipe": {"level": "high"}}


def test_rfc5424_format():
    msg = format_rfc5424(EVENT, app_name="siempipe", hostname="host 1", facility=13)
    assert msg.startswith(b"<108>1 2026-11-17T10:00:00.000+00:00 host1 siempipe - auth.login_failed - \xef\xbb\xbf{")
    alert = format_rfc5424(ALERT, app_name="siempipe", hostname="h", facility=13)
    assert alert.startswith(b"<107>1 ") and b" abc - " in alert  # high -> err(3), msgid = rule id


def test_syslog_tcp_octet_counting():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    received = bytearray()

    def serve():
        conn, _ = server.accept()
        with conn:
            while chunk := conn.recv(65536):
                received.extend(chunk)

    t = threading.Thread(target=serve)
    t.start()
    SyslogSink("127.0.0.1", server.getsockname()[1], "tcp", hostname="h").send([EVENT, EVENT])
    t.join(5)
    server.close()
    length, rest = bytes(received).split(b" ", 1)
    assert len(rest[: int(length)]) == int(length)
    assert rest[int(length):].split(b" ", 1)[0].isdigit()  # second frame starts with its length


class _Collector(BaseHTTPRequestHandler):
    bodies: list = []
    status = 200

    def do_POST(self):  # noqa: N802
        type(self).bodies.append((self.headers.get("Authorization"), self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def http_server():
    _Collector.bodies, _Collector.status = [], 200
    srv = HTTPServer(("127.0.0.1", 0), _Collector)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://localhost:{srv.server_address[1]}/collect", _Collector
    srv.shutdown()


def test_http_splunk_hec(http_server, monkeypatch):
    url, collector = http_server
    monkeypatch.setenv("HEC_TOKEN", "t0ken")
    HttpSink(url, "splunk_hec", token_env="HEC_TOKEN", index="ot").send([EVENT])
    auth, body = collector.bodies[0]
    assert auth == "Splunk t0ken"
    item = json.loads(body)
    assert item["index"] == "ot" and item["event"]["event"]["action"] == "auth.login_failed"


def test_http_token_env_required(monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    with pytest.raises(ValueError):
        HttpSink("https://siem.example/x", token_env="NOPE")


class _Flaky:
    def __init__(self):
        self.fail = True
        self.got = []

    def send(self, records):
        if self.fail:
            raise ConnectionRefusedError("down")
        self.got.extend(records)


def test_reliable_sink_spools_and_retries(tmp_path):
    inner = _Flaky()
    sink = ReliableSink(inner, tmp_path / "s.spool.jsonl", retry_base=0, retry_max=0, batch_size=2)
    sink.send([{"n": 1}, {"n": 2}, {"n": 3}])
    assert sink.pending == 3
    sink.send([{"n": 4}])
    assert sink.pending == 4
    inner.fail = False
    sink.send([{"n": 5}])
    assert [r["n"] for r in inner.got] == [1, 2, 3, 4, 5]
    assert sink.pending == 0


def test_reliable_sink_caps_spool(tmp_path):
    sink = ReliableSink(_Flaky(), tmp_path / "s.jsonl", retry_base=0, retry_max=0, max_spool_records=2)
    sink.send([{"n": i} for i in range(5)])
    assert sink.pending == 2


def test_build_sink(tmp_path):
    assert isinstance(build_sink({"type": "file", "path": str(tmp_path / "x")}, tmp_path, "e"), FileSink)
    assert isinstance(build_sink({"type": "syslog", "host": "h"}, tmp_path, "e"), ReliableSink)
    with pytest.raises(ValueError):
        build_sink({"type": "kafka"}, tmp_path, "e")
