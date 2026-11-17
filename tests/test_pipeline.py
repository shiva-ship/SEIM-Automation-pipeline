import json
from pathlib import Path

from siempipe.cli import main
from siempipe.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]


def test_end_to_end_run_once(tmp_path):
    log = tmp_path / "audit.log"
    lines = [f'2026-11-17 10:00:0{i},000 {{"event": "auth.login_failed", "ip": "10.0.0.9"}}' for i in range(5)]
    lines.append('2026-11-17 10:01:00,000 {"event": "agent.result", "agent": "fw-cell-01", "task": "t", '
                 '"overall": "mismatch", "mismatches": "serial_number"}')
    log.write_text("\n".join(lines) + "\n")
    (tmp_path / "assets.yml").write_text("agents:\n  fw-cell-01: {zone: cell-1, criticality: high}\n")
    cfg = tmp_path / "pipeline.yml"
    cfg.write_text(f"""
state_dir: state
sources:
  - name: securoty
    type: securoty_audit
    path: audit.log
    timezone: UTC
detections:
  rules: [{ROOT / 'detections' / 'rules'}]
enrichment:
  assets: assets.yml
outputs:
  events: [{{type: file, path: {tmp_path / 'events.jsonl'}}}]
  alerts: [{{type: file, path: {tmp_path / 'alerts.jsonl'}}}]
""")
    pipe = Pipeline.from_config(cfg)
    pipe.run(once=True)
    events = (tmp_path / "events.jsonl").read_text().splitlines()
    alerts = [json.loads(a) for a in (tmp_path / "alerts.jsonl").read_text().splitlines()]
    assert len(events) == 6
    names = sorted(a["rule"]["name"] for a in alerts)
    assert names == ["SecurOTy agent found device not matching the KeePass inventory",
                     "SecurOTy login brute force from one source"]
    mismatch = next(a for a in alerts if a["rule"]["category"] == "single-event")
    assert mismatch["asset"] == {"name": "fw-cell-01", "zone": "cell-1", "criticality": "high"}

    # second run: checkpoint means nothing is re-sent
    Pipeline.from_config(cfg).run(once=True)
    assert len((tmp_path / "events.jsonl").read_text().splitlines()) == 6


def test_replay_sample_log(capsys):
    assert main(["replay", str(ROOT / "samples" / "securoty_audit_attack.log"), "--timezone", "Europe/Berlin"]) == 0
    alerts = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len({a["rule"]["id"] for a in alerts}) >= 8
