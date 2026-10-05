"""Persistent app settings (JSON at ~/.config/mitui/settings.json)."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from . import paths
from .util import gen_secret

DEFAULTS: dict = {
    # local listeners
    "mixed_port": 7890,
    "redir_port": 0,
    "tproxy_port": 0,
    # core
    "mode": "rule",                       # rule | global | direct
    "log_level": "info",
    "controller": "127.0.0.1:9090",
    "secret": "",                         # generated on first run
    "mihomo_path": "",                    # empty: autodetect on PATH
    "unified_delay": True,
    "tcp_concurrent": True,
    # routing / dns
    "dns_enable": True,
    "fake_ip": True,
    "tun": False,                         # needs root or CAP_NET_ADMIN
    "tun_stack": "system",
    # node defaults applied to parsed share links
    "udp": True,
    "skip_cert_verify": False,
    # behaviour
    "test_url": "http://www.gstatic.com/generate_204",
    "test_timeout": 3000,
    "auto_group_interval": 300,
    "user_agent": "clash.meta/1.19.0",
    "fetch_via_proxy": "",                # e.g. http://127.0.0.1:7890
    "autostart_core": True,               # start the core when the TUI opens
    # state
    "subscriptions": [],                  # [{name, url, updated, count, info}]
    "selected": "",                       # chosen node in the PROXY group
    "extra_nodes": [],                    # manually added share links (parsed)
}

PROXY_GROUP = "PROXY"
AUTO_GROUP = "AUTO"
# mihomo's built-in selector, used instead of the rules in global mode
GLOBAL_GROUP = "GLOBAL"


class Settings:
    def __init__(self, data: dict | None = None) -> None:
        self.data: dict = dict(DEFAULTS)
        if data:
            for key, val in data.items():
                if key in DEFAULTS or key.startswith("x_"):
                    self.data[key] = val
        if not self.data.get("secret"):
            self.data["secret"] = gen_secret()

    # dict-ish access ------------------------------------------------------ #
    def __getitem__(self, key: str) -> Any:
        return self.data.get(key, DEFAULTS.get(key))

    def __setitem__(self, key: str, val: Any) -> None:
        self.data[key] = val

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    # persistence ---------------------------------------------------------- #
    @classmethod
    def load(cls) -> "Settings":
        try:
            with open(paths.SETTINGS_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            data = {}
        obj = cls(data if isinstance(data, dict) else {})
        if not paths.SETTINGS_FILE.exists():
            obj.save()
        return obj

    def save(self) -> None:
        paths.ensure_dirs()
        target = paths.SETTINGS_FILE
        fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".settings-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            os.replace(tmp, target)
            os.chmod(target, 0o600)   # the controller secret lives in here
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # subscriptions -------------------------------------------------------- #
    @property
    def subs(self) -> list:
        subs = self.data.get("subscriptions")
        if not isinstance(subs, list):
            subs = []
            self.data["subscriptions"] = subs
        return subs

    def find_sub(self, name: str) -> dict | None:
        for sub in self.subs:
            if sub.get("name") == name:
                return sub
        return None

    def add_sub(self, url: str, name: str = "") -> dict:
        url = url.strip()
        if not url:
            raise ValueError("empty URL")
        for sub in self.subs:
            if sub.get("url") == url:
                return sub
        if not name:
            name = _auto_name(url, {s.get("name", "") for s in self.subs})
        sub = {"name": name, "url": url, "updated": 0, "count": 0,
               "nodes": [], "info": {}}
        self.subs.append(sub)
        return sub

    def remove_sub(self, name: str) -> bool:
        for i, sub in enumerate(self.subs):
            if sub.get("name") == name:
                del self.subs[i]
                return True
        return False

    def all_nodes(self) -> list:
        """Every node from every subscription plus manual ones, deduped."""
        from .subs import dedupe

        out = []
        for sub in self.subs:
            for node in sub.get("nodes") or []:
                if isinstance(node, dict) and node.get("name"):
                    out.append(dict(node))
        for node in self.data.get("extra_nodes") or []:
            if isinstance(node, dict) and node.get("name"):
                out.append(dict(node))
        return dedupe(out)


def _auto_name(url: str, taken: set) -> str:
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname or "sub"
    base = host.split(".")[-2] if host.count(".") >= 1 else host
    base = base or "sub"
    name = base
    i = 2
    while name in taken:
        name = "%s-%d" % (base, i)
        i += 1
    return name
