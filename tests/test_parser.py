from siempipe.schema import get_field
from siempipe.sources import parse_securoty_line


def test_login_failed_maps_to_ecs():
    ev = parse_securoty_line('2026-11-17 11:20:00,123 {"event": "auth.login_failed", "ip": "10.0.0.5"}')
    assert ev["@timestamp"] == "2026-11-17T11:20:00.123Z"
    assert get_field(ev, "event.action") == "auth.login_failed"
    assert get_field(ev, "event.category") == ["authentication"]
    assert get_field(ev, "event.outcome") == "failure"
    assert get_field(ev, "source.ip") == "10.0.0.5"
    assert get_field(ev, "event.original").endswith('"10.0.0.5"}')


def test_local_timestamp_is_converted_to_utc():
    ev = parse_securoty_line('2026-07-01 12:00:00,000 {"event": "server.start"}', timezone="Europe/Berlin")
    assert ev["@timestamp"] == "2026-07-01T10:00:00.000Z"  # CEST = UTC+2


def test_python_repr_summary_is_decoded_and_sets_outcome():
    line = ('2026-11-17 06:40:00,000 {"event": "update.finished", "job": "j", "state": "failed", '
            '"dry_run": false, "summary": "{\'failed\': 1, \'aborted\': 0, \'succeeded\': 2}"}')
    ev = parse_securoty_line(line)
    assert get_field(ev, "securoty.summary.failed") == 1
    assert get_field(ev, "securoty.dry_run") is False
    assert get_field(ev, "event.outcome") == "failure"


def test_macs_list_and_count():
    line = '2026-11-17 06:40:00,000 {"event": "assets.neighbors_new", "source": "fw", "macs": "[\'aa:bb\', \'cc:dd\']"}'
    ev = parse_securoty_line(line)
    assert get_field(ev, "securoty.macs") == ["aa:bb", "cc:dd"]
    assert get_field(ev, "securoty.macs_count") == 2


def test_truncated_repr_is_kept_as_string():
    line = '2026-11-17 06:40:00,000 {"event": "assets.neighbors_new", "macs": "[\'aa:bb\', \'cc:"}'
    assert get_field(parse_securoty_line(line), "securoty.macs") == "['aa:bb', 'cc:"


def test_actor_and_agent_result():
    ev = parse_securoty_line('2026-11-17 06:40:00,000 {"event": "agent.result", "agent": "fw", '
                             '"task": "t", "overall": "mismatch", "mismatches": "serial_number,ip_address"}')
    assert get_field(ev, "securoty.mismatches") == ["serial_number", "ip_address"]
    assert get_field(ev, "event.outcome") == "failure"
    ev = parse_securoty_line('2026-11-17 06:40:00,000 {"event": "assets.cleared", "by": 2, "count": 1}')
    assert get_field(ev, "user.id") == "2"


def test_unknown_action_is_kept():
    ev = parse_securoty_line('2026-11-17 06:40:00,000 {"event": "something.new", "x": 1}')
    assert get_field(ev, "event.action") == "something.new"
    assert get_field(ev, "event.outcome") == "unknown"


def test_garbage_lines_are_rejected():
    for line in ["", "hello", "2026-11-17 06:40:00,000 not json", '2026-11-17 06:40:00,000 {"no_event": 1}',
                 '2026-11-17 06:40:00,000 {"event": "x", broken}']:
        assert parse_securoty_line(line) is None
