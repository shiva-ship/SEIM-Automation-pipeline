import os

from siempipe.tail import FileFollower


def test_partial_lines_and_commit(tmp_path):
    log = tmp_path / "audit.log"
    state = tmp_path / "state.json"
    log.write_text("one\ntwo\nthr")
    f = FileFollower(log, state)
    assert f.read() == ["one", "two"]
    assert f.read() == ["one", "two"]  # not committed yet -> same lines again (at-least-once)
    f.commit()
    with log.open("a") as fh:
        fh.write("ee\n")
    assert f.read() == ["three"]
    f.commit()
    assert FileFollower(log, state).read() == []  # checkpoint survives restart


def test_rotation_drains_old_file(tmp_path):
    log = tmp_path / "audit.log"
    state = tmp_path / "state.json"
    log.write_text("a\n")
    f = FileFollower(log, state)
    assert f.read() == ["a"]
    f.commit()
    with log.open("a") as fh:
        fh.write("b\n")
    os.replace(log, tmp_path / "audit.log.1")  # RotatingFileHandler behaviour
    log.write_text("c\n")
    assert f.read() == ["b", "c"]


def test_truncation_restarts_from_zero(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("aaaa\nbbbb\n")
    f = FileFollower(log, tmp_path / "s.json")
    f.read()
    f.commit()
    log.write_text("c\n")
    assert f.read() == ["c"]


def test_start_at_end_and_missing_file(tmp_path):
    log = tmp_path / "audit.log"
    assert FileFollower(log, tmp_path / "s1.json").read() == []
    log.write_text("old\n")
    f = FileFollower(log, tmp_path / "s2.json", start_at="end")
    with log.open("a") as fh:
        fh.write("new\n")
    assert f.read() == ["new"]
