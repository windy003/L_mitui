"""Application state and operations shared by the TUI and the CLI."""

from __future__ import annotations

import time
from collections import deque

from . import confgen, paths, subs
from .api import Api, ApiError
from .core import Core, CoreError, log_tail
from .settings import AUTO_GROUP, GLOBAL_GROUP, PROXY_GROUP, Settings

UNTESTED = None
TIMEOUT = -1


class App:
    def __init__(self, st: Settings | None = None) -> None:
        paths.ensure_dirs()
        self.st = st or Settings.load()
        self.core = Core(self.st)
        self.nodes: list = self.st.all_nodes()
        self.delays: dict = {}        # name -> ms, or TIMEOUT
        self.now: str = str(self.st["selected"] or "")
        self.logs: deque = deque(maxlen=1000)
        self.up = 0
        self.down = 0
        self.up_total = 0
        self.down_total = 0
        self.conns = 0
        self.core_version = ""
        self.status = ""
        self.status_err = False
        self.status_at = 0.0
        # set when nodes/settings changed but the core has not been reloaded yet
        self.dirty = not paths.CORE_CONFIG.exists()

    # ------------------------------------------------------------------ #
    def api(self) -> Api:
        return Api(str(self.st["controller"]), str(self.st["secret"]))

    def say(self, msg: str, err: bool = False) -> None:
        self.status = msg
        self.status_err = err
        self.status_at = time.time()
        if msg:
            self.logs.append("[mitui] %s" % msg)

    def reload_nodes(self) -> None:
        self.nodes = self.st.all_nodes()
        names = {n["name"] for n in self.nodes}
        self.delays = {k: v for k, v in self.delays.items() if k in names}

    def node_by_name(self, name: str) -> dict | None:
        for node in self.nodes:
            if node.get("name") == name:
                return node
        return None

    # subscriptions ----------------------------------------------------- #
    def update_sub(self, sub: dict) -> int:
        """Fetch one subscription and store its nodes. Returns the node count."""
        text, info = subs.fetch(
            sub["url"],
            ua=str(self.st["user_agent"]),
            proxy=str(self.st["fetch_via_proxy"] or ""),
        )
        nodes = subs.parse(text)
        if not nodes:
            raise subs.SubError("no usable nodes in the response "
                                "(got %d bytes)" % len(text))
        sub["nodes"] = nodes
        sub["count"] = len(nodes)
        sub["updated"] = time.time()
        sub["info"] = info
        self.st.save()
        self.reload_nodes()
        return len(nodes)

    def update_all(self) -> tuple:
        ok, failed = 0, []
        for sub in self.st.subs:
            try:
                ok += self.update_sub(sub)
            except Exception as exc:
                failed.append("%s: %s" % (sub.get("name"), exc))
        return ok, failed

    def add_sub(self, url: str, name: str = "") -> dict:
        sub = self.st.add_sub(url, name)
        self.st.save()
        return sub

    def add_link(self, uri: str) -> dict:
        """Add a single share link (trojan://...) as a standalone node."""
        node = subs.parse_uri(uri.strip())
        if not node:
            raise ValueError("not a recognised share link")
        extra = list(self.st["extra_nodes"] or [])
        extra = [n for n in extra if n.get("name") != node["name"]]
        extra.append(node)
        self.st["extra_nodes"] = extra
        self.st.save()
        self.reload_nodes()
        return node

    # config ------------------------------------------------------------- #
    def write_config(self) -> str:
        return confgen.write(self.st, self.nodes)

    def apply(self) -> str:
        """Regenerate the config and push it into a running core (or start it)."""
        path = self.write_config()
        if not self.core.is_running():
            return "config written to %s" % path
        try:
            self.api().reload(path)
        except ApiError as exc:
            raise CoreError("reload failed: %s" % exc) from exc
        self.restore_selection()
        return "config reloaded (%d nodes)" % len(self.nodes)

    def _push_selection(self, name: str) -> None:
        """Point both selectors at ``name``.

        In rule mode traffic reaches our PROXY group; in global mode mihomo
        ignores the rules and uses its built-in GLOBAL selector instead, so
        setting only PROXY would silently do nothing in that mode.
        """
        api = self.api()
        api.select(PROXY_GROUP, name)
        try:
            api.select(GLOBAL_GROUP, name)
        except ApiError:
            pass

    def restore_selection(self) -> None:
        wanted = str(self.st["selected"] or "")
        if not wanted:
            return
        if wanted != AUTO_GROUP and not self.node_by_name(wanted):
            return
        try:
            self._push_selection(wanted)
            self.now = wanted
        except ApiError:
            pass

    # core --------------------------------------------------------------- #
    def _validate(self) -> str:
        """Write the config and check everything a start depends on.

        Returns a note to show the user; raises CoreError if a start cannot
        possibly succeed.
        """
        # Binary and privilege checks come first: failing them must not leave a
        # regenerated config.yaml that disagrees with the core still running.
        self.core.preflight(require_config=False)
        self.write_config()
        self.core.test_config()
        self.core.preflight()
        return ""

    def start_core(self, detached: bool = False) -> str:
        note = self._validate()
        pid = self.core.start(detached=detached)
        self.restore_selection()
        self.dirty = False
        return "core running (pid %d)%s" % (pid, note)

    def stop_core(self) -> str:
        if self.core.stop():
            return "core stopped"
        return "core was not running"

    def restart_core(self, detached: bool = False) -> str:
        # Validate first: if the new config or the privileges are wrong we keep
        # the currently running core instead of leaving the user with no proxy.
        note = self._validate()
        if self.core.is_running():
            self.core.stop()
        pid = self.core.start(detached=detached)
        self.restore_selection()
        self.dirty = False
        return "core restarted (pid %d)%s" % (pid, note)

    def set_mode(self, mode: str) -> str:
        mode = mode.lower()
        self.st["mode"] = mode
        self.st.save()
        if self.core.is_running():
            self.api().set_mode(mode)
            # GLOBAL starts out on DIRECT, which looks like a dead proxy the
            # moment the user switches to global mode -- carry the choice over.
            if mode == "global":
                self.restore_selection()
        return "mode: %s" % mode

    def select(self, name: str) -> str:
        if not self.core.is_running():
            self.st["selected"] = name
            self.st.save()
            return "saved selection: %s (core not running)" % name
        self._push_selection(name)
        self.st["selected"] = name
        self.st.save()
        self.now = name
        return "using %s" % name

    # live data ----------------------------------------------------------- #
    def refresh_proxies(self) -> None:
        """Pull the current selection and cached latencies from the core."""
        data = self.api().proxies()
        group = data.get(PROXY_GROUP)
        if isinstance(group, dict) and group.get("now"):
            self.now = str(group["now"])
        for name, item in data.items():
            if not isinstance(item, dict):
                continue
            history = item.get("history") or []
            if not history or not isinstance(history[-1], dict):
                continue
            delay = history[-1].get("delay")
            if isinstance(delay, int):
                self.delays[name] = delay if delay > 0 else TIMEOUT

    def refresh_version(self) -> None:
        try:
            info = self.api().version()
            self.core_version = str(info.get("version") or "")
        except ApiError:
            self.core_version = ""

    def test_all(self) -> tuple:
        """Latency-test every node. Returns (tested, failed)."""
        api = self.api()
        url = str(self.st["test_url"])
        timeout = int(self.st["test_timeout"])
        names = [n["name"] for n in self.nodes]
        if not names:
            return 0, 0
        result: dict = {}
        try:
            result = api.group_delay(AUTO_GROUP, url, timeout)
        except ApiError:
            result = {}
        if result and not any(k in ("message", "error") for k in result):
            for name in names:
                value = result.get(name)
                self.delays[name] = value if isinstance(value, int) and value > 0 \
                    else TIMEOUT
            ok = sum(1 for n in names if self.delays.get(n, TIMEOUT) > 0)
            return len(names), len(names) - ok
        # group endpoint unavailable (older core): fall back to one by one
        ok = 0
        for name in names:
            try:
                self.delays[name] = api.delay(name, url, timeout)
                ok += 1
            except ApiError:
                self.delays[name] = TIMEOUT
        return len(names), len(names) - ok

    def test_one(self, name: str) -> int:
        try:
            value = self.api().delay(name, str(self.st["test_url"]),
                                     int(self.st["test_timeout"]))
        except ApiError:
            self.delays[name] = TIMEOUT
            raise
        self.delays[name] = value
        return value

    def refresh_conns(self) -> None:
        try:
            data = self.api().connections()
        except ApiError:
            return
        self.conns = len(data.get("connections") or [])
        self.up_total = int(data.get("uploadTotal") or 0)
        self.down_total = int(data.get("downloadTotal") or 0)

    def load_file_logs(self, n: int = 200) -> None:
        for line in log_tail(n):
            self.logs.append(line)
