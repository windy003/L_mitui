"""Filesystem layout (XDG based)."""

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
# mihomo working directory: it keeps GeoIP.dat / geoip.metadb / cache.db here.
CORE_HOME = DATA_DIR / "core"
CORE_CONFIG = CORE_HOME / "config.yaml"
NODES_CACHE = DATA_DIR / "nodes.json"
LOG_FILE = DATA_DIR / "mihomo.log"
# Deliberately NOT in XDG_RUNTIME_DIR: that directory is wiped when the last
# session of the user ends, which would hide a still running core from us (and
# let a second one start on the same port). A stale pid here is harmless --
# pid_alive() verifies the process really is the core before trusting it.
PID_FILE = DATA_DIR / "mihomo.pid"
BIN_DIR = DATA_DIR / "bin"


def ensure_dirs() -> None:
    for d in (CONFIG_DIR, DATA_DIR, CACHE_DIR, CORE_HOME, BIN_DIR):
        d.mkdir(parents=True, exist_ok=True)
