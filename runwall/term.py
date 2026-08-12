"""Terminal output helpers.

Windows consoles still default to cp1252, which cannot encode box-drawing
characters or check marks. Rather than degrading every operator-facing surface
to ASCII, try to switch the stream to UTF-8 and fall back cleanly when that is
not possible. A security tool whose output crashes on the default Windows
console is a security tool people stop running.
"""
from __future__ import annotations

import os
import sys

_ANSI = {"reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
         "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
         "cyan": "\033[36m", "mag": "\033[35m", "blue": "\033[34m"}

_UNICODE = {"ok": "✓", "bad": "✗", "rule": "─", "dot": "·",
            "arrow": "→", "ellipsis": "…", "warn": "!"}
_ASCII = {"ok": "+", "bad": "x", "rule": "-", "dot": "*",
          "arrow": "->", "ellipsis": "...", "warn": "!"}


def init() -> tuple[dict, dict]:
    """Prepare stdout. Returns (colors, glyphs), either of which may be inert."""
    unicode_ok = True
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError, ValueError):
        enc = (getattr(sys.stdout, "encoding", "") or "").lower()
        unicode_ok = enc.replace("-", "") in ("utf8", "utf16", "utf32")

    colors = dict(_ANSI)
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        colors = {k: "" for k in _ANSI}

    return colors, (_UNICODE if unicode_ok else _ASCII)


def rule(glyphs: dict, width: int = 96) -> str:
    return glyphs["rule"] * width
