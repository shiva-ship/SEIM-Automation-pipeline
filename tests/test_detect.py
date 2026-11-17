import datetime as dt

import pytest

from siempipe.detect import Engine, RuleError, parse_rule_document


def rule(detection, level="medium", rid="r1", **extra):
    return parse_rule_document({"id": rid, "title": rid, "level": level, "detection": detection, **extra})


def ev(**fields):
    base = {"@timestamp": "2026-11-17T10:00:00Z"}
    for k, v in fields.items():
        cur = base
        *parents, leaf = k.split("__")
        for p in parents:
            cur = cur.setdefault(p, {})
        cur[leaf] = v
    return base


def test_modifiers():
    r = rule({"sel": {"a|contains": "bad", "b|startswith": "10.", "c|endswith": ".exe", "n|gte": 3},
              "condition": "sel"})
    assert r.matcher(ev(a="xxBADxx", b="10.1.2.3", c="evil.EXE", n=3))
    assert not r.matcher(ev(a="good", b="10.1.2.3", c="evil.exe", n=3))
    assert not r.matcher(ev(a="bad", b="10.1.2.3", c="evil.exe", n=2))


def test_wildcards_case_insensitive_lists_and_null():
    r = rule({"sel": {"a": ["foo*", "bar"], "missing": None}, "condition": "sel"})
    assert r.matcher(ev(a="FOOtball"))
    assert r.matcher(ev(a="Bar"))
    assert not r.matcher(ev(a="baz"))
    assert not r.matcher(ev(a="bar", missing="x"))


def test_cidr_re_all_and_list_values():
    r = rule({"sel": {"ip|cidr": "10.20.0.0/16", "tags|all": ["x", "y"], "msg|re": r"^err\d+$"},
              "condition": "sel"})
    assert r.matcher(ev(ip="10.20.5.5", tags=["x", "y", "z"], msg="err42"))
    assert not r.matcher(ev(ip="10.21.5.5", tags=["x", "y"], msg="err42"))
    assert not r.matcher(ev(ip="10.20.5.5", tags=["x"], msg="err42"))


def test_booleans():
    r = rule({"sel": {"flag": False}, "condition": "sel"})
    assert r.matcher(ev(flag=False))
    assert not r.matcher(ev(flag=True))
    assert not r.matcher(ev())


def test_condition_grammar():
    det = {"sel_a": {"a": 1}, "sel_b": {"b": 1}, "filter": {"c": 1}}
    assert rule({**det, "condition": "1 of sel_* and not filter"}).matcher(ev(b=1))
    assert not rule({**det, "condition": "1 of sel_* and not filter"}).matcher(ev(b=1, c=1))
    assert rule({**det, "condition": "all of sel_*"}).matcher(ev(a=1, b=1))
    assert not rule({**det, "condition": "all of sel_*"}).matcher(ev(a=1))
    assert rule({**det, "condition": "sel_a or (sel_b and filter)"}).matcher(ev(b=1, c=1))
    assert rule({**det, "condition": "1 of them"}).matcher(ev(c=1))
    assert rule({**det, "condition": ["sel_a", "sel_b"]}).matcher(ev(b=1))


@pytest.mark.parametrize("detection", [
    {"sel": {"a|base64": "x"}, "condition": "sel"},
    {"sel": {"a": 1}, "condition": "nope"},
    {"sel": {"a": 1}, "condition": "sel and"},
    {"sel": {"a": 1}, "condition": "(sel"},
    {"sel": ["keyword"], "condition": "sel"},
    {"sel": {"a": 1}},
])
def test_invalid_rules_are_rejected(detection):
    with pytest.raises(RuleError):
        rule(detection)


def test_level_must_be_valid():
    with pytest.raises(RuleError):
        rule({"sel": {"a": 1}, "condition": "sel"}, level="urgent")


def _corr(**kw):
    doc = {"id": "c1", "title": "c1", "level": "high",
           "correlation": {"type": "event_count", "rules": ["base"], "group-by": ["src"],
                           "timespan": "1m", "condition": {"gte": 3}, **kw}}
    return parse_rule_document(doc)


def _base():
    return parse_rule_document({"id": "b1", "name": "base", "title": "b", "level": "low",
                                "detection": {"s": {"x": 1}, "condition": "s"}})


def _at(seconds, src="a"):
    ts = dt.datetime(2026, 11, 17, tzinfo=dt.UTC) + dt.timedelta(seconds=seconds)
    return {"@timestamp": ts.isoformat(), "x": 1, "src": src}


def test_correlation_window_grouping_and_suppression_of_base_rule():
    engine = Engine([_base(), _corr()])
    alerts = [a for s, src in [(0, "a"), (10, "b"), (20, "a"), (30, "a")] for a in engine.process(_at(s, src))]
    assert len(alerts) == 1  # base rule does not alert on its own (generate: false)
    assert alerts[0]["rule"]["id"] == "c1"
    assert alerts[0]["siempipe"]["correlation"]["group"] == {"src": "a"}
    assert alerts[0]["siempipe"]["correlation"]["count"] == 3


def test_correlation_window_expires():
    engine = Engine([_base(), _corr()])
    assert not [a for s in (0, 40, 80, 120) for a in engine.process(_at(s))]


def test_correlation_generate_true_keeps_base_alerts():
    engine = Engine([_base(), _corr(generate=True)])
    alerts = [a for s in (0, 1, 2) for a in engine.process(_at(s))]
    assert [a["rule"]["id"] for a in alerts] == ["b1", "b1", "b1", "c1"]


def test_engine_rejects_bad_references_and_duplicates():
    with pytest.raises(RuleError):
        Engine([_corr()])
    with pytest.raises(RuleError):
        Engine([_base(), _base()])
