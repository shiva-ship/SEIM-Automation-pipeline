"""Command line: ``siempipe run | replay | test-rules | convert``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .detect import Engine, RuleError, load_rules
from .enrich import Enricher
from .pipeline import Pipeline, Source
from .ruletest import run_rule_tests
from .sinks import StdoutSink

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = ROOT / "detections" / "rules"
DEFAULT_TESTS = ROOT / "detections" / "tests"


def _cmd_run(args) -> int:
    Pipeline.from_config(Path(args.config)).run(once=args.once)
    return 0


def _cmd_replay(args) -> int:
    if args.config:
        pipe = Pipeline.from_config(Path(args.config), with_outputs=False)
    else:
        pipe = Pipeline(Enricher(), Engine(load_rules([Path(p) for p in args.rules])))
    source = Source("replay", "securoty_audit", None, {"timezone": args.timezone})
    lines = Path(args.file).read_text(encoding="utf-8").splitlines()
    events, alerts = pipe.process(lines, source)
    out = StdoutSink()
    if args.events:
        out.send(events)
    out.send(alerts)
    s = pipe.stats
    print(f"# {s.lines} lines, {s.events} events, {s.unparsed} unparsed, {len(alerts)} alerts", file=sys.stderr)
    for name, count in s.alerts.most_common():
        print(f"#   {count:4d}  {name}", file=sys.stderr)
    return 0


def _cmd_test(args) -> int:
    failures = run_rule_tests([Path(p) for p in args.rules], Path(args.tests), verbose=True)
    return 1 if failures else 0


def _cmd_convert(args) -> int:
    try:
        from sigma.collection import SigmaCollection
        from sigma.correlations import SigmaCorrelationRule
    except ImportError:
        print("pySigma is not installed: pip install 'siempipe[sigma]'", file=sys.stderr)
        return 2
    if args.target == "splunk":
        from sigma.backends.splunk import SplunkBackend as Backend
    else:
        from sigma.backends import elasticsearch

        Backend = {"esql": elasticsearch.ESQLBackend, "eql": elasticsearch.EqlBackend,
                   "lucene": elasticsearch.LuceneBackend}[args.target]

    files = sorted(p for d in args.rules for p in Path(d).rglob("*.yml"))
    collection = SigmaCollection.load_ruleset(files)
    backend = Backend()
    errors = 0
    for rule in collection:
        is_corr = isinstance(rule, SigmaCorrelationRule)
        try:
            queries = backend.convert_correlation_rule(rule) if is_corr else backend.convert_rule(rule)
        except NotImplementedError as exc:
            print(f"SKIP  {rule.title}: {exc}", file=sys.stderr)
            continue
        except Exception as exc:  # noqa: BLE001 - report every rule that fails to convert
            errors += 1
            print(f"ERROR {rule.title}: {exc}", file=sys.stderr)
            continue
        if not queries:  # base rule that only feeds a correlation
            continue
        if args.json:
            print(json.dumps({"id": str(rule.id), "title": rule.title, "queries": queries}))
        else:
            print(f"# {rule.title} ({rule.id})")
            for q in queries:
                print(q)
            print()
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="siempipe", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="follow configured sources and forward events/alerts")
    p.add_argument("-c", "--config", required=True)
    p.add_argument("--once", action="store_true", help="process what is there, then exit")
    p.set_defaults(func=_cmd_run)

    p = sub.add_parser("replay", help="run detections over a SecurOTy audit log and print alerts")
    p.add_argument("file")
    p.add_argument("-c", "--config", help="use enrichment/rules from this config")
    p.add_argument("--rules", nargs="+", default=[str(DEFAULT_RULES)])
    p.add_argument("--timezone", default="UTC", help="timezone of the audit log timestamps")
    p.add_argument("--events", action="store_true", help="also print normalized events")
    p.set_defaults(func=_cmd_replay)

    p = sub.add_parser("test-rules", help="run detection test cases")
    p.add_argument("--rules", nargs="+", default=[str(DEFAULT_RULES)])
    p.add_argument("--tests", default=str(DEFAULT_TESTS))
    p.set_defaults(func=_cmd_test)

    p = sub.add_parser("convert", help="convert Sigma rules to SIEM queries (needs siempipe[sigma])")
    p.add_argument("--target", choices=["splunk", "esql", "eql", "lucene"], default="splunk",
                   help="lucene has no correlation support; use esql or eql for Elastic")
    p.add_argument("--rules", nargs="+", default=[str(DEFAULT_RULES)])
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_convert)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        return args.func(args)
    except RuleError as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
