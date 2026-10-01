"""配置/缓存目录（遵循 XDG 规范）。"""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "mihomo-tui"


def _base(env: str, default: str) -> Path:
    return Path(os.environ.get(env) or (Path.home() / default))


def config_dir() -> Path:
    d = _base("XDG_CONFIG_HOME", ".config") / APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def cache_dir() -> Path:
    d = _base("XDG_CACHE_HOME", ".cache") / APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def bin_dir() -> Path:
    d = config_dir() / "bin"
    d.mkdir(parents=True, exist_ok=True)
    return d


def settings_file() -> Path:
    return config_dir() / "settings.json"


def nodes_file() -> Path:
    return config_dir() / "nodes.json"


def core_config() -> Path:
    """生成给 mihomo 读取的 config.yaml。"""
    return config_dir() / "config.yaml"
