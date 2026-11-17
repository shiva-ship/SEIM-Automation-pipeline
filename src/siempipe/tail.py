"""Follow a log file across rotations with a persisted checkpoint (at-least-once).

SecurOTy rotates ``audit.log`` with ``RotatingFileHandler`` (``audit.log`` ->
``audit.log.1`` ...). When the inode of the followed path changes, the rest of
the previous file is drained from its rotated name before continuing with the
new one, so no lines are lost at rotation time.

Call :meth:`FileFollower.read` to get new complete lines, and
:meth:`FileFollower.commit` only after they were delivered.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


class FileFollower:
    def __init__(self, path: Path, state_file: Path, *, start_at: str = "beginning", max_rotated: int = 10):
        self.path = Path(path)
        self.state_file = Path(state_file)
        self.max_rotated = max_rotated
        self._state = self._load()
        self._pending: dict | None = None
        if not self._state and start_at == "end" and self.path.exists():
            st = self.path.stat()
            self._state = {"inode": st.st_ino, "offset": st.st_size}

    def _load(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _find_rotated(self, inode: int) -> Path | None:
        for i in range(1, self.max_rotated + 1):
            candidate = self.path.with_name(f"{self.path.name}.{i}")
            try:
                if candidate.stat().st_ino == inode:
                    return candidate
            except FileNotFoundError:
                continue
        return None

    @staticmethod
    def _read_from(path: Path, offset: int, *, complete_only: bool) -> tuple[list[str], int]:
        with path.open("rb") as fh:
            fh.seek(offset)
            data = fh.read()
        if complete_only:
            cut = data.rfind(b"\n") + 1
            data = data[:cut]
        lines = [ln.decode("utf-8", errors="replace") for ln in data.splitlines()]
        return lines, offset + len(data)

    def read(self) -> list[str]:
        """Return new complete lines since the last commit (does not advance the checkpoint)."""
        state = dict(self._state)
        lines: list[str] = []
        try:
            st = self.path.stat()
        except FileNotFoundError:
            st = None

        inode, offset = state.get("inode"), int(state.get("offset", 0))
        if inode is not None and (st is None or st.st_ino != inode):
            old = self._find_rotated(inode)
            if old is not None:
                drained, _ = self._read_from(old, offset, complete_only=False)
                lines.extend(drained)
            offset = 0
        elif st is not None and st.st_size < offset:  # truncated in place
            offset = 0

        if st is not None:
            new, offset = self._read_from(self.path, offset, complete_only=True)
            lines.extend(new)
            state = {"inode": st.st_ino, "offset": offset}
        else:
            state = {}
        self._pending = state
        return [ln for ln in lines if ln.strip()]

    def commit(self) -> None:
        if self._pending is None:
            return
        self._state = self._pending
        self._pending = None
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state), encoding="utf-8")
        os.replace(tmp, self.state_file)
