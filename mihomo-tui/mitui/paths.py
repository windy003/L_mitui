"""文件布局（遵循 XDG 规范）。"""

from __future__ import annotations

import os
from pathlib import Path

APP = "mitui"


def _xdg(env: str, fallback: str) -> Path:
    raw = os.environ.get(env)
    if raw:
        return Path(raw).expanduser()
    return Path.home() / fallback


CONFIG_DIR = _xdg("XDG_CONFIG_HOME", ".config") / APP
DATA_DIR = _xdg("XDG_DATA_HOME", ".local/share") / APP
CACHE_DIR = _xdg("XDG_CACHE_HOME", ".cache") / APP

SETTINGS_FILE = CONFIG_DIR / "settings.json"
# mihomo 的工作目录：GeoIP.dat / geoip.metadb / cache.db 都放在这里。
CORE_HOME = DATA_DIR / "core"
CORE_CONFIG = CORE_HOME / "config.yaml"
NODES_CACHE = DATA_DIR / "nodes.json"
LOG_FILE = DATA_DIR / "mihomo.log"
# 故意不放在 XDG_RUNTIME_DIR：用户最后一个会话结束时那个目录会被清空，
# 于是仍在运行的内核就被我们漏掉了（还可能在同一端口上再起第二个）。
# 这里留下过期的 pid 没有害处 —— pid_alive() 会先确认那个进程真的是内核
# 才采信它。
PID_FILE = DATA_DIR / "mihomo.pid"
BIN_DIR = DATA_DIR / "bin"


def ensure_dirs() -> None:
    for d in (CONFIG_DIR, DATA_DIR, CACHE_DIR, CORE_HOME, BIN_DIR):
        d.mkdir(parents=True, exist_ok=True)
