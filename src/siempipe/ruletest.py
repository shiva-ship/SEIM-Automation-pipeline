"""Detection-as-code tests.

Each file in ``detections/tests/`` describes cases for one rule (by rule id)::

    rule: 5f1c...            # rule id (or correlation id)
    enrichment:              # optional, same shape as the pipeline config
      maintenance_windows: [...]
    cases:
      - name: five failures from one IP
        expect: 1            # number of alerts of *this* rule
        timezone: UTC        # optional
        lines: |
          2026-11-17 10:00:00,000 {"event": "auth.login_failed", "ip": "10.0.0.5"}

Every rule must have at least one true-positive (expect > 0) and one
true-negative (expect: 0) case; rules without tests fail the suite.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .detect import Correlation, Engine, load_rules
from .enrich import Enricher, MaintenanceWindow
from .sources import parse_securoty_line


def load_test_files(tests_dir: Path) -> list[tuple[Path, dict]]:
    return [(p, yaml.safe_load(p.read_text(encoding="utf-8"))) for p in sorted(Path(tests_dir).glob("*.yml"))]


def run_case(rule_dirs: list[Path], rule_id: str, case: dict, enrichment: dict | None) -> int:
    """Run one case on a fresh engine; return the number of alerts for ``rule_id``."""
    engine = Engine(load_rules(rule_dirs))
    enrichment = enrichment or {}
    enricher = Enricher(
        enrichment.get("assets"),
        [MaintenanceWindow.from_config(w) for w in enrichment.get("maintenance_windows") or []],
    )
    count = 0
    for line in str(case.get("lines", "")).splitlines():
        event = parse_securoty_line(line, timezone=case.get("timezone", "UTC"))
        if event is None:
            continue
        for alert in engine.process(enricher.enrich(event)):
            if alert["rule"]["id"] == rule_id:
                count += 1
    return count


def run_rule_tests(rule_dirs: list[Path], tests_dir: Path, *, verbose: bool = False) -> list[str]:
    all_rules = load_rules(rule_dirs)
    # A base rule that only feeds a correlation (generate: false) needs no own tests.
    feeding = {ref for r in all_rules if isinstance(r, Correlation) and not r.generate for ref in r.rules}
    alerting = {r.id: r for r in all_rules if not (r.id in feeding or (r.name and r.name in feeding))}

    failures: list[str] = []
    covered: dict[str, set[str]] = {}
    for path, spec in load_test_files(tests_dir):
        rule_id = str(spec.get("rule"))
        if rule_id not in alerting:
            failures.append(f"{path.name}: unknown or non-alerting rule id {rule_id}")
            continue
        for case in spec.get("cases") or []:
            got = run_case(rule_dirs, rule_id, case, spec.get("enrichment"))
            want = int(case.get("expect", 0))
            covered.setdefault(rule_id, set()).add("tp" if want > 0 else "tn")
            ok = got == want
            if verbose:
                print(f"{'PASS' if ok else 'FAIL'}  {alerting[rule_id].title} :: {case.get('name')}"
                      + ("" if ok else f" (expected {want}, got {got})"))
            if not ok:
                failures.append(f"{path.name}: {case.get('name')}: expected {want}, got {got}")

    for rule_id, rule in alerting.items():
        kinds = covered.get(rule_id, set())
        for kind, label in (("tp", "true-positive"), ("tn", "true-negative")):
            if kind not in kinds:
                failures.append(f"{rule.title}: no {label} test case")
    if verbose:
        print(f"\n{len(alerting)} rules, {len(failures)} failure(s)")
        for f in failures:
            print(f"  - {f}")
    return failures
