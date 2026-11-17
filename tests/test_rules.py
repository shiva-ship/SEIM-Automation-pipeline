from pathlib import Path

from siempipe.detect import load_rules
from siempipe.ruletest import run_rule_tests

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "detections" / "rules"
TESTS = ROOT / "detections" / "tests"


def test_all_rules_load():
    assert len(load_rules([RULES])) >= 10


def test_every_detection_passes_its_cases():
    assert run_rule_tests([RULES], TESTS) == []
