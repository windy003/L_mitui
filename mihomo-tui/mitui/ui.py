"""The curses terminal interface."""

from __future__ import annotations

import curses
import locale
import queue
import threading

from .api import ApiError
from .confgen import geo_db_present
from .core import tun_ready
from .settings import AUTO_GROUP
from .subs import SubError
from .util import ago, dwidth, human_bytes, human_rate, pad, trunc, ts_str

TABS = ("Nodes", "Subs", "Logs", "Settings")
MODES = ("rule", "global", "direct")
SORTS = ("default", "delay", "name", "type")

# colour pair ids
C_HEAD = 1
C_ACCENT = 2
C_DIM = 3
C_GOOD = 4
C_WARN = 5
C_BAD = 6
C_SEL = 7
C_TAB = 8

SECRET_KEYS = ("password", "uuid", "auth-str", "obfs-password", "secret",
               "private-key", "pre-shared-key", "token", "psk", "auth")

SETTING_ITEMS = [
    ("mixed_port", "Mixed port (HTTP+SOCKS)", "int"),
    ("allow_lan", "Allow LAN", "bool"),
    ("mode", "Mode", "choice:rule,global,direct"),
    ("log_level", "Log level", "choice:silent,error,warning,info,debug"),
    ("tun", "TUN mode (needs root/setcap)", "bool"),
    ("tun_stack", "TUN stack", "choice:system,gvisor,mixed"),
    ("dns_enable", "Built-in DNS", "bool"),
    ("fake_ip", "fake-ip mode", "bool"),
    ("cn_direct", "Route CN traffic direct", "bool"),
    ("ipv6", "IPv6", "bool"),
    ("udp", "Enable UDP on nodes", "bool"),
    ("skip_cert_verify", "Skip TLS verify on all nodes", "bool"),
    ("test_url", "Latency test URL", "str"),
    ("test_timeout", "Latency timeout (ms)", "int"),
    ("auto_group_interval", "AUTO group retest interval (s)", "int"),
    ("user_agent", "Subscription User-Agent", "str"),
    ("fetch_via_proxy", "Fetch subs via proxy (blank = direct)", "str"),
    ("controller", "External controller", "str"),
    ("mihomo_path", "mihomo binary (blank = autodetect)", "str"),
    ("autostart_core", "Start core when mitui opens", "bool"),
]


def run(app) -> None:
    locale.setlocale(locale.LC_ALL, "")
    curses.wrapper(lambda scr: Ui(scr, app).loop())


class Ui:
    def __init__(self, scr, app) -> None:
        self.scr = scr
        self.app = app
        self.tab = 0
        self.cursor = {0: 0, 1: 0, 3: 0}
        self.offset = {0: 0, 1: 0, 3: 0}
        self.filter = ""
        self.sort = 0
        self.reveal = False
        self.follow = True
        self.log_offset = 0
        self.busy = ""
        self.q: queue.Queue = queue.Queue()
        self.stop_flag = threading.Event()
        self.quit = False

    # ------------------------------------------------------------------ #
    # plumbing
    # ------------------------------------------------------------------ #
    def loop(self) -> None:
        curses.curs_set(0)
        self.scr.nodelay(False)
        self.scr.timeout(250)
        self._init_colors()
        self.app.load_file_logs(100)

        threading.Thread(target=self._poller, daemon=True).start()
        threading.Thread(target=self._traffic_stream, daemon=True).start()
        threading.Thread(target=self._log_stream, daemon=True).start()

        if self.app.st["autostart_core"] and not self.app.core.is_running():
            if self.app.nodes or self.app.st.subs:
                self.spawn("starting core", self.app.start_core)

        while not self.quit:
            self._drain()
            self.draw()
            try:
                ch = self.scr.getch()
            except KeyboardInterrupt:
                ch = ord("q")
            if ch == -1:
                continue
            if ch == curses.KEY_RESIZE:
                continue
            self.on_key(ch)
        self.stop_flag.set()

    def _init_colors(self) -> None:
        self.color = False
        try:
            curses.start_color()
            curses.use_default_colors()
        except curses.error:
            return
        if curses.COLORS < 8:
            return
        self.color = True
        bg = -1
        curses.init_pair(C_HEAD, curses.COLOR_CYAN, bg)
        curses.init_pair(C_ACCENT, curses.COLOR_MAGENTA, bg)
        curses.init_pair(C_DIM, curses.COLOR_WHITE, bg)
        curses.init_pair(C_GOOD, curses.COLOR_GREEN, bg)
        curses.init_pair(C_WARN, curses.COLOR_YELLOW, bg)
        curses.init_pair(C_BAD, curses.COLOR_RED, bg)
        curses.init_pair(C_SEL, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(C_TAB, curses.COLOR_BLACK, curses.COLOR_WHITE)

    def cp(self, pair: int) -> int:
        return curses.color_pair(pair) if self.color else 0

    def spawn(self, label: str, fn, *args) -> None:
        """Run a blocking operation off the UI thread."""
        self.busy = label

        def work():
            try:
                self.q.put(("ok", label, fn(*args)))
            except Exception as exc:
                self.q.put(("err", label, exc))

        threading.Thread(target=work, daemon=True).start()

    def _drain(self) -> None:
        while True:
            try:
                kind, label, payload = self.q.get_nowait()
            except queue.Empty:
                return
            self.busy = ""
            if kind == "err":
                self.app.say("%s: %s" % (label, _oneline(payload)), err=True)
            else:
                self.app.say(_oneline(payload) if payload else "%s done" % label)

    # background streams ------------------------------------------------- #
    def _poller(self) -> None:
        tick = 0
        while not self.stop_flag.is_set():
            try:
                if self.app.core.is_running():
                    if not self.app.core_version or tick % 20 == 0:
                        self.app.refresh_version()
                    self.app.refresh_proxies()
                    if tick % 2 == 0:
                        self.app.refresh_conns()
                else:
                    self.app.core_version = ""
                    self.app.up = self.app.down = 0
            except Exception:
                pass
            tick += 1
            self.stop_flag.wait(2.0)

    def _traffic_stream(self) -> None:
        while not self.stop_flag.is_set():
            if not self.app.core.is_running():
                self.stop_flag.wait(1.0)
                continue
            try:
                for item in self.app.api().traffic():
                    if self.stop_flag.is_set():
                        return
                    self.app.up = int(item.get("up") or 0)
                    self.app.down = int(item.get("down") or 0)
            except Exception:
                pass
            self.stop_flag.wait(1.0)

    def _log_stream(self) -> None:
        while not self.stop_flag.is_set():
            if not self.app.core.is_running():
                self.stop_flag.wait(1.0)
                continue
            try:
                for item in self.app.api().logs(str(self.app.st["log_level"])):
                    if self.stop_flag.is_set():
                        return
                    self.app.logs.append("%-7s %s" % (
                        str(item.get("type", "")).upper(),
                        str(item.get("payload", "")),
                    ))
            except Exception:
                pass
            self.stop_flag.wait(1.0)

    # ------------------------------------------------------------------ #
    # drawing
    # ------------------------------------------------------------------ #
    def put(self, y: int, x: int, text: str, attr: int = 0,
            width: int = 0) -> None:
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x < 0 or x >= w:
            return
        # Never touch the last cell of the line: writing it can wrap or raise.
        limit = w - x - 1
        if width:
            limit = min(limit, width)
        if limit <= 0:
            return
        try:
            self.scr.addstr(y, x, trunc(text, limit), attr)
        except curses.error:
            pass

    def draw(self) -> None:
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        if h < 8 or w < 40:
            self.put(0, 0, "terminal too small", self.cp(C_BAD))
            self.scr.refresh()
            return
        self.draw_header(w)
        self.draw_tabs(3, w)
        body_top, body_h = 4, h - 6
        if self.tab == 0:
            self.draw_nodes(body_top, body_h, w)
        elif self.tab == 1:
            self.draw_subs(body_top, body_h, w)
        elif self.tab == 2:
            self.draw_logs(body_top, body_h, w)
        else:
            self.draw_settings(body_top, body_h, w)
        self.draw_footer(h, w)
        self.scr.refresh()

    def draw_header(self, w: int) -> None:
        app = self.app
        title = " mitui "
        self.put(0, 0, title, self.cp(C_HEAD) | curses.A_BOLD)
        sub = "mihomo TUI client"
        self.put(0, dwidth(title) + 1, sub, self.cp(C_DIM) | curses.A_DIM)
        right = "%d nodes" % len(app.nodes)
        if getattr(app, "dirty", False):
            right += " *unapplied"
        self.put(0, max(0, w - dwidth(right) - 2), right, self.cp(C_ACCENT))

        running = app.core.is_running()
        x = 0
        if running:
            label = "● running"
            attr = self.cp(C_GOOD) | curses.A_BOLD
        else:
            label = "○ stopped"
            attr = self.cp(C_BAD) | curses.A_BOLD
        self.put(1, x, label, attr)
        x += dwidth(label) + 2
        bits = []
        if app.core_version:
            bits.append("v%s" % app.core_version.lstrip("v"))
        bits.append("mode:%s" % app.st["mode"])
        bits.append("port:%s" % app.st["mixed_port"])
        if app.st["tun"]:
            bits.append("tun")
        if app.st["cn_direct"] and not geo_db_present():
            bits.append("geoip:missing")
        node = app.now or app.st["selected"] or "-"
        bits.append("node:%s" % trunc(str(node), 24))
        info = "  ".join(bits)
        self.put(1, x, info, self.cp(C_DIM))
        x += dwidth(info) + 2
        rates = "↑%s ↓%s" % (human_rate(app.up), human_rate(app.down))
        if app.conns:
            rates += "  conn:%d" % app.conns
        self.put(1, max(x, w - dwidth(rates) - 2), rates,
                 self.cp(C_ACCENT) if (app.up or app.down) else self.cp(C_DIM))
        self.put(2, 0, "─" * max(0, w - 1), self.cp(C_DIM) | curses.A_DIM)

    def draw_tabs(self, y: int, w: int) -> None:
        x = 0
        for i, name in enumerate(TABS):
            label = " %d %s " % (i + 1, name)
            if i == self.tab:
                self.put(y, x, label, self.cp(C_TAB) | curses.A_BOLD)
            else:
                self.put(y, x, label, self.cp(C_DIM) | curses.A_DIM)
            x += dwidth(label) + 1
        if self.filter and self.tab == 0:
            self.put(y, x + 2, "/%s" % self.filter, self.cp(C_WARN))
        if self.sort and self.tab == 0:
            tag = "sort:%s" % SORTS[self.sort]
            self.put(y, max(0, w - dwidth(tag) - 2), tag, self.cp(C_DIM))

    # nodes -------------------------------------------------------------- #
    def visible_nodes(self) -> list:
        nodes = list(self.app.nodes)
        if self.filter:
            needle = self.filter.lower()
            nodes = [n for n in nodes
                     if needle in str(n.get("name", "")).lower()
                     or needle in str(n.get("type", "")).lower()
                     or needle in str(n.get("server", "")).lower()]
        key = SORTS[self.sort]
        if key == "delay":
            def rank(n):
                d = self.app.delays.get(n["name"])
                if d is None:
                    return (2, 0)
                if d <= 0:
                    return (1, 0)
                return (0, d)
            nodes.sort(key=rank)
        elif key == "name":
            nodes.sort(key=lambda n: str(n.get("name", "")).lower())
        elif key == "type":
            nodes.sort(key=lambda n: (str(n.get("type", "")),
                                      str(n.get("name", "")).lower()))
        return nodes

    def draw_nodes(self, top: int, height: int, w: int) -> None:
        nodes = self.visible_nodes()
        if not nodes:
            msg = ("No nodes yet. Press 2 for the Subs tab, then n to add a "
                   "subscription URL (or L to paste a trojan:// link).")
            self.put(top + 1, 2, msg, self.cp(C_WARN))
            return
        detail_w = 38 if w >= 96 else 0
        list_w = w - detail_w - (2 if detail_w else 0)

        delay_w, type_w = 9, 10
        name_w = max(12, int((list_w - delay_w - type_w - 6) * 0.55))
        server_w = max(0, list_w - delay_w - type_w - name_w - 6)

        self.put(top, 2, pad("NAME", name_w) + " " + pad("TYPE", type_w) + " "
                 + pad("SERVER", server_w) + " " + pad("DELAY", delay_w),
                 self.cp(C_DIM) | curses.A_BOLD | curses.A_UNDERLINE, list_w)

        rows = height - 2
        idx = self._clamp(0, len(nodes), rows)
        for row in range(rows):
            i = self.offset[0] + row
            if i >= len(nodes):
                break
            node = nodes[i]
            y = top + 1 + row
            name = str(node.get("name", ""))
            current = name == (self.app.now or self.app.st["selected"])
            selected = i == idx
            base = self.cp(C_SEL) if selected else 0
            mark = "▶" if current else " "
            self.put(y, 0, mark + (" " if selected else " "),
                     (self.cp(C_GOOD) | curses.A_BOLD) if current and not selected
                     else base)
            line = (pad(name, name_w) + " " + pad(str(node.get("type", "")), type_w)
                    + " " + pad(str(node.get("server", "")), server_w) + " ")
            self.put(y, 2, line, base | (curses.A_BOLD if current else 0),
                     list_w - 2)
            dtext, dattr = self._delay_cell(name)
            self.put(y, 2 + dwidth(line), pad(dtext, delay_w),
                     base if selected else dattr, delay_w)

        if len(nodes) > rows:
            self.put(top + height - 1, 2, "%d-%d of %d" % (
                self.offset[0] + 1, min(self.offset[0] + rows, len(nodes)),
                len(nodes)), self.cp(C_DIM) | curses.A_DIM)
        if detail_w:
            self.draw_detail(top, height, w - detail_w, detail_w,
                             nodes[idx] if nodes else None)

    def _delay_cell(self, name: str) -> tuple:
        value = self.app.delays.get(name)
        if value is None:
            return "-", self.cp(C_DIM) | curses.A_DIM
        if value <= 0:
            return "timeout", self.cp(C_BAD)
        if value < 200:
            return "%dms" % value, self.cp(C_GOOD)
        if value < 600:
            return "%dms" % value, self.cp(C_WARN)
        return "%dms" % value, self.cp(C_BAD)

    def draw_detail(self, top: int, height: int, x: int, width: int,
                    node) -> None:
        for y in range(top, top + height):
            self.put(y, x - 1, "│", self.cp(C_DIM) | curses.A_DIM)
        if not node:
            return
        self.put(top, x + 1, "DETAILS", self.cp(C_DIM) | curses.A_BOLD
                 | curses.A_UNDERLINE, width - 2)
        y = top + 1
        for key, value in node.items():
            if y >= top + height:
                break
            shown = self._fmt_value(key, value)
            self.put(y, x + 1, pad(str(key), 16), self.cp(C_DIM), 16)
            self.put(y, x + 18, shown, 0, width - 19)
            y += 1
        if y < top + height - 1 and not self.reveal:
            self.put(top + height - 1, x + 1, "p: reveal secrets",
                     self.cp(C_DIM) | curses.A_DIM)

    def _fmt_value(self, key: str, value) -> str:
        if isinstance(value, dict):
            return "{%s}" % ", ".join("%s=%s" % (k, v) for k, v in value.items())
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        text = str(value)
        if key in SECRET_KEYS and not self.reveal and text:
            return text[:3] + "•" * max(3, min(10, len(text) - 3))
        return text

    # subs --------------------------------------------------------------- #
    def draw_subs(self, top: int, height: int, w: int) -> None:
        items = self.app.st.subs
        extra = self.app.st["extra_nodes"] or []
        if not items and not extra:
            self.put(top + 1, 2, "No subscriptions. Press n to add a URL, "
                     "or L to add a single trojan:// link.", self.cp(C_WARN))
            return
        name_w = max(10, min(22, w // 4))
        self.put(top, 2, pad("NAME", name_w) + " " + pad("NODES", 7) + " "
                 + pad("UPDATED", 12) + " " + "QUOTA / URL",
                 self.cp(C_DIM) | curses.A_BOLD | curses.A_UNDERLINE)
        rows = max(1, height - 3)
        idx = self._clamp(1, len(items), rows)
        for row in range(rows):
            i = self.offset[1] + row
            if i >= len(items):
                break
            sub = items[i]
            y = top + 1 + row
            attr = self.cp(C_SEL) if i == idx else 0
            info = sub.get("info") or {}
            quota = _quota_text(info)
            line = (pad(str(sub.get("name", "")), name_w) + " "
                    + pad(str(sub.get("count", 0)), 7) + " "
                    + pad(ago(sub.get("updated")), 12) + " "
                    + (quota or str(sub.get("url", ""))))
            self.put(y, 2, line, attr, w - 3)
        if extra:
            y = top + 1 + min(len(items), rows) + 1
            self.put(y, 2, "manual links: %d node(s)  (stored separately)"
                     % len(extra), self.cp(C_DIM) | curses.A_DIM)
        if items and 0 <= idx < len(items):
            sub = items[idx]
            info = sub.get("info") or {}
            y = top + height - 1
            detail = "url: %s" % sub.get("url", "")
            if info.get("expire"):
                detail += "   expires: %s" % ts_str(info.get("expire"))
            self.put(y, 2, detail, self.cp(C_DIM) | curses.A_DIM, w - 3)

    # logs --------------------------------------------------------------- #
    def draw_logs(self, top: int, height: int, w: int) -> None:
        lines = list(self.app.logs)
        rows = height - 1
        if self.follow:
            self.log_offset = max(0, len(lines) - rows)
        start = max(0, min(self.log_offset, max(0, len(lines) - rows)))
        for row in range(rows):
            i = start + row
            if i >= len(lines):
                break
            line = lines[i]
            attr = 0
            low = line.lower()
            if "error" in low or "fatal" in low:
                attr = self.cp(C_BAD)
            elif "warn" in low:
                attr = self.cp(C_WARN)
            elif line.startswith("[mitui]"):
                attr = self.cp(C_ACCENT)
            self.put(top + row, 1, line, attr, w - 2)
        tag = "follow" if self.follow else "paused  (f to follow)"
        self.put(top + height - 1, 1, "%s · %d lines" % (tag, len(lines)),
                 self.cp(C_DIM) | curses.A_DIM)

    # settings ----------------------------------------------------------- #
    def draw_settings(self, top: int, height: int, w: int) -> None:
        rows = max(1, height - 2)
        idx = self._clamp(3, len(SETTING_ITEMS), rows)
        label_w = max(24, min(42, w // 2))
        for row in range(rows):
            i = self.offset[3] + row
            if i >= len(SETTING_ITEMS):
                break
            key, label, kind = SETTING_ITEMS[i]
            value = self.app.st[key]
            y = top + row
            attr = self.cp(C_SEL) if i == idx else 0
            if kind == "bool":
                shown = "[x] on" if value else "[ ] off"
                vattr = self.cp(C_GOOD) if value else self.cp(C_DIM)
            else:
                shown = str(value) if value not in (None, "") else "(unset)"
                vattr = 0 if value not in (None, "") else \
                    self.cp(C_DIM) | curses.A_DIM
            self.put(y, 2, pad(label, label_w), attr, label_w)
            self.put(y, 2 + label_w + 1, shown, attr if i == idx else vattr,
                     w - label_w - 4)
        self.put(top + height - 1, 2,
                 "enter: toggle/edit    a: write config + reload core",
                 self.cp(C_DIM) | curses.A_DIM)

    # footer ------------------------------------------------------------- #
    def draw_footer(self, h: int, w: int) -> None:
        msg = self.app.status
        if self.busy:
            msg = "… %s" % self.busy
        attr = self.cp(C_BAD) if (self.app.status_err and not self.busy) \
            else self.cp(C_GOOD)
        if self.busy:
            attr = self.cp(C_WARN)
        self.put(h - 2, 1, msg, attr, w - 2)
        hints = {
            0: "enter select  t/T test  / filter  o sort  s start  x stop  "
               "r restart  m mode  ? help  q quit",
            1: "n new  enter/u update  U update all  L add link  d delete  "
               "a apply  ? help  q quit",
            2: "f follow  c clear  ↑↓ scroll  s start  x stop  r restart  "
               "? help  q quit",
            3: "enter toggle/edit  a apply  r restart core  ? help  q quit",
        }[self.tab]
        self.put(h - 1, 1, hints, self.cp(C_DIM) | curses.A_DIM, w - 2)

    # ------------------------------------------------------------------ #
    # cursor helpers
    # ------------------------------------------------------------------ #
    def _clamp(self, tab: int, total: int, rows: int) -> int:
        idx = self.cursor.get(tab, 0)
        idx = max(0, min(idx, max(0, total - 1)))
        off = self.offset.get(tab, 0)
        if idx < off:
            off = idx
        elif idx >= off + rows:
            off = idx - rows + 1
        off = max(0, min(off, max(0, total - rows)))
        self.cursor[tab] = idx
        self.offset[tab] = off
        return idx

    def _move(self, delta: int, total: int) -> None:
        if self.tab == 2:
            self.follow = False
            self.log_offset = max(0, self.log_offset + delta)
            return
        if total <= 0:
            return
        self.cursor[self.tab] = max(0, min(self.cursor.get(self.tab, 0) + delta,
                                           total - 1))

    def _count(self) -> int:
        if self.tab == 0:
            return len(self.visible_nodes())
        if self.tab == 1:
            return len(self.app.st.subs)
        if self.tab == 3:
            return len(SETTING_ITEMS)
        return len(self.app.logs)

    # ------------------------------------------------------------------ #
    # input
    # ------------------------------------------------------------------ #
    def on_key(self, ch: int) -> None:
        total = self._count()
        if ch in (curses.KEY_DOWN, ord("j")):
            return self._move(1, total)
        if ch in (curses.KEY_UP, ord("k")):
            return self._move(-1, total)
        if ch in (curses.KEY_NPAGE, 6):
            return self._move(10, total)
        if ch in (curses.KEY_PPAGE, 2):
            return self._move(-10, total)
        if ch == ord("g"):
            if self.tab == 2:
                self.follow = False
                self.log_offset = 0
            else:
                self.cursor[self.tab] = 0
            return
        if ch == ord("G"):
            if self.tab == 2:
                self.follow = True
            else:
                self.cursor[self.tab] = max(0, total - 1)
            return
        if ch in (ord("\t"), curses.KEY_RIGHT):
            self.tab = (self.tab + 1) % len(TABS)
            return
        if ch in (curses.KEY_BTAB, curses.KEY_LEFT):
            self.tab = (self.tab - 1) % len(TABS)
            return
        if ord("1") <= ch <= ord("4"):
            self.tab = ch - ord("1")
            return
        if ch == ord("?"):
            return self.help_screen()
        if ch == 27:                 # esc clears the filter, never quits
            self.filter = ""
            return
        if ch == ord("q"):
            return self.try_quit()

        # core control (available everywhere)
        if ch == ord("s"):
            return self.spawn("starting core", self.app.start_core)
        if ch == ord("x"):
            return self.spawn("stopping core", self.app.stop_core)
        if ch == ord("r"):
            return self.spawn("restarting core", self._restart)
        if ch == ord("m"):
            cur = str(self.app.st["mode"]).lower()
            nxt = MODES[(MODES.index(cur) + 1) % len(MODES)] \
                if cur in MODES else "rule"
            return self.spawn("switching mode", self.app.set_mode, nxt)
        if ch == ord("a"):
            return self.spawn("applying config", self._apply)
        if ch == ord("L"):
            return self.add_link()

        if self.tab == 0:
            return self.keys_nodes(ch, total)
        if self.tab == 1:
            return self.keys_subs(ch)
        if self.tab == 2:
            return self.keys_logs(ch)
        return self.keys_settings(ch)

    # per-tab keys -------------------------------------------------------- #
    def keys_nodes(self, ch: int, total: int) -> None:
        nodes = self.visible_nodes()
        idx = self.cursor.get(0, 0)
        node = nodes[idx] if 0 <= idx < len(nodes) else None
        if ch in (10, 13, curses.KEY_ENTER):
            if node:
                self.spawn("selecting node", self.app.select, node["name"])
            return
        if ch == ord("t") and node:
            return self.spawn("testing %s" % node["name"], self._test_one,
                              node["name"])
        if ch == ord("T"):
            return self.spawn("testing all nodes", self._test_all)
        if ch == ord("A"):
            return self.spawn("selecting AUTO", self.app.select, AUTO_GROUP)
        if ch == ord("D"):
            return self.spawn("selecting DIRECT", self.app.select, "DIRECT")
        if ch == ord("/"):
            text = self.prompt("filter: ", self.filter)
            if text is not None:
                self.filter = text.strip()
                self.cursor[0] = 0
            return
        if ch == ord("o"):
            self.sort = (self.sort + 1) % len(SORTS)
            return
        if ch == ord("p"):
            self.reveal = not self.reveal
            return
        if ch == ord("c"):
            if self.confirm("Close all active connections?"):
                self.spawn("closing connections", self._close_conns)
            return
        if ch == ord("y") and node:
            self.app.say("node: %s  %s:%s" % (node["name"], node.get("server"),
                                              node.get("port")))

    def keys_subs(self, ch: int) -> None:
        items = self.app.st.subs
        idx = self.cursor.get(1, 0)
        sub = items[idx] if 0 <= idx < len(items) else None
        if ch == ord("n"):
            url = self.prompt("subscription URL: ")
            if not url:
                return
            name = self.prompt("name (blank = auto): ") or ""
            try:
                new = self.app.add_sub(url.strip(), name.strip())
            except ValueError as exc:
                return self.app.say(str(exc), err=True)
            return self.spawn("fetching %s" % new["name"], self._update_one, new)
        if ch in (10, 13, curses.KEY_ENTER, ord("u")) and sub:
            return self.spawn("updating %s" % sub.get("name"),
                              self._update_one, sub)
        if ch == ord("U"):
            return self.spawn("updating all subscriptions", self._update_all)
        if ch == ord("d") and sub:
            if self.confirm("Delete subscription '%s'?" % sub.get("name")):
                self.app.st.remove_sub(str(sub.get("name")))
                self.app.st.save()
                self.app.reload_nodes()
                self.app.dirty = True
                self.app.say("deleted %s" % sub.get("name"))
            return
        if ch == ord("c"):
            if self.app.st["extra_nodes"] and \
                    self.confirm("Remove all manually added links?"):
                self.app.st["extra_nodes"] = []
                self.app.st.save()
                self.app.reload_nodes()
                self.app.dirty = True

    def keys_logs(self, ch: int) -> None:
        if ch == ord("f"):
            self.follow = not self.follow
            return
        if ch == ord("c"):
            self.app.logs.clear()
            return
        if ch == ord("R"):
            self.app.load_file_logs(200)

    def keys_settings(self, ch: int) -> None:
        idx = self.cursor.get(3, 0)
        if not (0 <= idx < len(SETTING_ITEMS)):
            return
        key, label, kind = SETTING_ITEMS[idx]
        if ch not in (10, 13, curses.KEY_ENTER, ord(" ")):
            return
        if kind == "bool":
            self.app.st[key] = not bool(self.app.st[key])
        elif kind.startswith("choice:"):
            options = kind.split(":", 1)[1].split(",")
            cur = str(self.app.st[key])
            nxt = options[(options.index(cur) + 1) % len(options)] \
                if cur in options else options[0]
            self.app.st[key] = nxt
        else:
            text = self.prompt("%s: " % label, str(self.app.st[key] or ""))
            if text is None:
                return
            text = text.strip()
            if kind == "int":
                try:
                    self.app.st[key] = int(text)
                except ValueError:
                    return self.app.say("not a number: %s" % text, err=True)
            else:
                self.app.st[key] = text
        self.app.st.save()
        self.app.dirty = True
        if key == "tun" and self.app.st[key] and not tun_ready(self.app.st):
            return self.app.say(
                "TUN needs privileges -- run: sudo setcap "
                "cap_net_admin,cap_net_bind_service=+ep \"$(command -v mihomo)\""
                "   (the core will refuse to start until then)", err=True)
        if key == "cn_direct" and self.app.st[key] and not geo_db_present():
            return self.app.say(
                "CN-direct needs the GeoIP database -- put Country.mmdb in "
                "the core directory (see the Status tab)", err=True)
        if key == "mode" and self.app.core.is_running():
            self.spawn("switching mode", self.app.set_mode,
                       str(self.app.st["mode"]))
        else:
            self.app.say("%s = %s  (press a to apply)" % (key, self.app.st[key]))

    # wrapped operations -------------------------------------------------- #
    def _apply(self) -> str:
        msg = self.app.apply()
        self.app.dirty = False
        return msg

    def _restart(self) -> str:
        msg = self.app.restart_core()
        self.app.dirty = False
        return msg

    def _update_one(self, sub: dict) -> str:
        count = self.app.update_sub(sub)
        self.app.dirty = True
        if self.app.core.is_running():
            self.app.apply()
            self.app.dirty = False
        return "%s: %d nodes" % (sub.get("name"), count)

    def _update_all(self) -> str:
        total, failed = self.app.update_all()
        self.app.dirty = True
        if self.app.core.is_running():
            self.app.apply()
            self.app.dirty = False
        if failed:
            raise SubError("%d nodes, %d failed: %s"
                           % (total, len(failed), "; ".join(failed)))
        return "%d nodes from %d subscription(s)" % (total, len(self.app.st.subs))

    def _test_one(self, name: str) -> str:
        try:
            value = self.app.test_one(name)
        except ApiError:
            return "%s: timeout" % name
        return "%s: %dms" % (name, value)

    def _test_all(self) -> str:
        tested, failed = self.app.test_all()
        return "tested %d nodes, %d unreachable" % (tested, failed)

    def _close_conns(self) -> str:
        self.app.api().close_connections()
        return "connections closed"

    # modals -------------------------------------------------------------- #
    def prompt(self, label: str, initial: str = ""):
        """Single line input. Returns None when cancelled."""
        h, w = self.scr.getmaxyx()
        buf = list(initial)
        curses.curs_set(1)
        self.scr.timeout(-1)
        try:
            while True:
                text = "".join(buf)
                self.scr.move(h - 2, 0)
                self.scr.clrtoeol()
                self.put(h - 2, 1, label, self.cp(C_WARN) | curses.A_BOLD)
                start = dwidth(label) + 2
                visible = text[-(max(10, w - start - 2)):]
                self.put(h - 2, start, visible)
                try:
                    self.scr.move(h - 2, min(w - 1, start + dwidth(visible)))
                except curses.error:
                    pass
                self.scr.refresh()
                ch = self.scr.getch()
                if ch in (10, 13, curses.KEY_ENTER):
                    return "".join(buf)
                if ch == 27:
                    return None
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    if buf:
                        buf.pop()
                    continue
                if ch == 21:            # ctrl-u
                    buf = []
                    continue
                if ch == 23:            # ctrl-w
                    while buf and buf[-1] == " ":
                        buf.pop()
                    while buf and buf[-1] != " ":
                        buf.pop()
                    continue
                if ch == curses.KEY_RESIZE:
                    h, w = self.scr.getmaxyx()
                    continue
                if 32 <= ch < 0x110000:
                    try:
                        buf.append(chr(ch))
                    except ValueError:
                        pass
        finally:
            curses.curs_set(0)
            self.scr.timeout(250)

    def confirm(self, question: str) -> bool:
        h, _ = self.scr.getmaxyx()
        self.scr.move(h - 2, 0)
        self.scr.clrtoeol()
        self.put(h - 2, 1, "%s [y/N] " % question,
                 self.cp(C_WARN) | curses.A_BOLD)
        self.scr.refresh()
        self.scr.timeout(-1)
        try:
            ch = self.scr.getch()
        finally:
            self.scr.timeout(250)
        return ch in (ord("y"), ord("Y"))

    def add_link(self) -> None:
        uri = self.prompt("share link (trojan://...): ")
        if not uri:
            return
        try:
            node = self.app.add_link(uri)
        except ValueError as exc:
            return self.app.say(str(exc), err=True)
        self.app.dirty = True
        self.app.say("added %s" % node["name"])
        if self.app.core.is_running():
            self.spawn("applying config", self._apply)

    def help_screen(self) -> None:
        lines = [
            "mitui — mihomo TUI client",
            "",
            "Tabs            1 Nodes   2 Subs   3 Logs   4 Settings   "
            "(Tab / ← →)",
            "Move            j/k or ↑/↓ · PgUp/PgDn · g top · G bottom",
            "",
            "Core            s start   x stop   r restart   m cycle mode",
            "                a  write config and reload the running core",
            "",
            "Nodes tab       enter  use this node",
            "                t      test latency of the highlighted node",
            "                T      test every node",
            "                A / D  switch to the AUTO group / DIRECT",
            "                /      filter   o sort   p reveal secrets",
            "                c      close all active connections",
            "",
            "Subs tab        n  add a subscription URL",
            "                enter / u  update   U update all",
            "                L  add one share link   d delete   c clear links",
            "",
            "Logs tab        f follow   c clear   R reload from log file",
            "",
            "Settings tab    enter toggle or edit, then a to apply",
            "",
            "Proxy for your shell:",
            "  export https_proxy=http://127.0.0.1:%s "
            "http_proxy=http://127.0.0.1:%s"
            % (self.app.st["mixed_port"], self.app.st["mixed_port"]),
            "",
            "press any key to close",
        ]
        self.scr.erase()
        for i, line in enumerate(lines):
            attr = self.cp(C_HEAD) | curses.A_BOLD if i == 0 else 0
            if line.endswith(":") or line.startswith("Proxy"):
                attr = self.cp(C_ACCENT)
            self.put(i + 1, 2, line, attr)
        self.scr.refresh()
        self.scr.timeout(-1)
        try:
            self.scr.getch()
        finally:
            self.scr.timeout(250)

    def try_quit(self) -> None:
        if self.app.core.owns_process():
            h, _ = self.scr.getmaxyx()
            self.scr.move(h - 2, 0)
            self.scr.clrtoeol()
            self.put(h - 2, 1,
                     "Quit: [k]eep the proxy running, [s]top it, [c]ancel? ",
                     self.cp(C_WARN) | curses.A_BOLD)
            self.scr.refresh()
            self.scr.timeout(-1)
            try:
                ch = self.scr.getch()
            finally:
                self.scr.timeout(250)
            if ch in (ord("c"), 27):
                return
            if ch in (ord("s"), ord("S")):
                self.app.core.stop()
            else:
                # detach: the child was started in its own session already
                from .core import read_pidfile, write_pidfile
                info = read_pidfile()
                if info:
                    info["detached"] = True
                    write_pidfile(info)
                self.app.core.proc = None
        self.quit = True


def _oneline(value) -> str:
    text = str(value).replace("\n", " · ").strip()
    return text[:400]


def _quota_text(info: dict) -> str:
    used = int(info.get("upload") or 0) + int(info.get("download") or 0)
    total = int(info.get("total") or 0)
    if not total:
        return ""
    pct = used * 100.0 / total if total else 0
    text = "%s / %s (%.0f%%)" % (human_bytes(used), human_bytes(total), pct)
    if info.get("expire"):
        text += "  exp %s" % ts_str(info.get("expire"))
    return text
