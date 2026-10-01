"""Small helpers shared across modules."""

from __future__ import annotations

import secrets
import time


def gen_secret(n: int = 16) -> str:
    return secrets.token_hex(n)


def human_bytes(n: float) -> str:
    units = ("B", "K", "M", "G", "T", "P")
    i = 0
    n = float(n)
    while n >= 1024.0 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    if i == 0:
        return "%d%s" % (n, units[i])
    if n >= 100:
        return "%.0f%s" % (n, units[i])
    return "%.1f%s" % (n, units[i])


def human_rate(n: float) -> str:
    return human_bytes(n) + "/s"


def ago(ts: float | None) -> str:
    if not ts:
        return "never"
    d = max(0, int(time.time() - ts))
    if d < 60:
        return "%ds ago" % d
    if d < 3600:
        return "%dm ago" % (d // 60)
    if d < 86400:
        return "%dh ago" % (d // 3600)
    return "%dd ago" % (d // 86400)


def ts_str(ts: float | None) -> str:
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def trunc(s: str, width: int) -> str:
    """Truncate to a display width, counting CJK characters as two columns."""
    if width <= 0:
        return ""
    out = []
    used = 0
    for ch in s:
        w = 2 if _wide(ch) else 1
        if used + w > width:
            if used + 1 <= width:
                out.append("~")
            break
        out.append(ch)
        used += w
    return "".join(out)


def dwidth(s: str) -> int:
    return sum(2 if _wide(ch) else 1 for ch in s)


def pad(s: str, width: int) -> str:
    s = trunc(s, width)
    return s + " " * max(0, width - dwidth(s))


def _wide(ch: str) -> bool:
    o = ord(ch)
    return (
        0x1100 <= o <= 0x115F
        or 0x2E80 <= o <= 0xA4CF
        or 0xAC00 <= o <= 0xD7A3
        or 0xF900 <= o <= 0xFAFF
        or 0xFE30 <= o <= 0xFE6F
        or 0xFF00 <= o <= 0xFF60
        or 0xFFE0 <= o <= 0xFFE6
        or 0x1F300 <= o <= 0x1FAFF
    )
