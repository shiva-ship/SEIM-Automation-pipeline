"""Log source parsers. Each parser turns one raw line into a normalized event (or None)."""

from .securoty import parse_securoty_line

PARSERS = {
    "securoty_audit": parse_securoty_line,
}

__all__ = ["PARSERS", "parse_securoty_line"]
