"""应用自身的设置，存 ~/.config/mihomo-tui/settings.json。"""
from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any

from .paths import nodes_file, settings_file

TEST_URL = "http://www.gstatic.com/generate_204"


@dataclass
class Subscription:
    name: str
    url: str
    updated: str = ""
    info: str = ""          # 机场返回的 subscription-userinfo
    count: int = 0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Subscription":
        return cls(
            name=d.get("name") or d.get("url", "")[:24],
            url=d.get("url", ""),
            updated=d.get("updated", ""),
            info=d.get("info", ""),
            count=int(d.get("count", 0) or 0),
        )


@dataclass
class Settings:
    subscriptions: list[Subscription] = field(default_factory=list)
    mixed_port: int = 7890
    controller: str = "127.0.0.1:9090"
    secret: str = ""
    mode: str = "rule"              # rule / global / direct
    log_level: str = "info"
    allow_lan: bool = False
    ipv6: bool = False
    tun: bool = False               # 需要 root / CAP_NET_ADMIN
    binary: str = ""                # 留空则自动在 PATH 与 bin 目录里找
    test_url: str = TEST_URL
    selected: str = ""              # 上次选中的节点
    autostart: bool = True
    skip_cert_verify: bool = False  # 对解析出的节点统一兜底

    # ---------- 持久化 ----------
    @classmethod
    def load(cls) -> "Settings":
        p = settings_file()
        if not p.exists():
            s = cls(secret=secrets.token_hex(8))
            s.save()
            return s
        try:
            raw = json.loads(p.read_text("utf-8"))
        except (OSError, ValueError):
            return cls(secret=secrets.token_hex(8))
        subs = [Subscription.from_dict(x) for x in raw.pop("subscriptions", []) if x.get("url")]
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        kwargs = {k: v for k, v in raw.items() if k in known}
        s = cls(**kwargs)
        s.subscriptions = subs
        if not s.secret:
            s.secret = secrets.token_hex(8)
        return s

    def save(self) -> None:
        d = asdict(self)
        settings_file().write_text(
            json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    @property
    def api_base(self) -> str:
        return f"http://{self.controller}"


def load_nodes() -> list[dict[str, Any]]:
    """读取上次抓取到的节点缓存，离线也能启动。"""
    p = nodes_file()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text("utf-8"))
    except (OSError, ValueError):
        return []
    return [n for n in data if isinstance(n, dict) and n.get("name")]


def save_nodes(nodes: list[dict[str, Any]]) -> None:
    nodes_file().write_text(
        json.dumps(nodes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
