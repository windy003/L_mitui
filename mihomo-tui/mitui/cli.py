"""Command line entry point. With no arguments it opens the TUI."""

from __future__ import annotations

import argparse
import sys

from . import __version__, paths
from .api import ApiError
from .app import App
from .core import CoreError, install_core, log_tail, read_pidfile
from .settings import AUTO_GROUP, PROXY_GROUP
from .subs import SubError
from .util import ago, human_bytes


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Accept --allow-root anywhere, including after the subcommand, since that
    # is how people naturally retype it from the refusal message.
    allow_root = "--allow-root" in argv
    argv = [a for a in argv if a != "--allow-root"]
    parser = build_parser()
    args = parser.parse_args(argv)
    args.allow_root = allow_root
    # Keep stdout and stderr interleaved in the right order when the output is
    # piped or redirected (stdout would be block buffered otherwise).
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError):
        pass
    if _is_sudo() and not args.allow_root:
        _warn_sudo()
        return 2
    if sys.platform == "win32":
        print("mitui targets Linux (it supervises the mihomo core and uses "
              "POSIX signals).", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except (CoreError, SubError, ApiError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    except OSError as exc:
        # unwritable config/data directory, full disk, bad permissions...
        print("error: %s" % exc, file=sys.stderr)
        return 1


def _is_sudo() -> bool:
    """Started through sudo: root's HOME is not where the user's config lives."""
    import os

    return (hasattr(os, "geteuid") and os.geteuid() == 0
            and bool(os.environ.get("SUDO_USER")))


def _warn_sudo() -> None:
    """Explain the actual hazard, which depends on whether sudo kept HOME."""
    import os

    user = os.environ.get("SUDO_USER", "")
    user_config = ""
    try:
        import pwd

        home = pwd.getpwnam(user).pw_dir
        user_config = os.path.join(home, ".config", "mitui")
    except (ImportError, KeyError):
        pass

    current = str(paths.CONFIG_DIR)
    if user_config and os.path.normpath(user_config) != os.path.normpath(current):
        hazard = (
            "As root, mitui reads %s -- root's own, empty profile. Your\n"
            "subscriptions and nodes are in %s, so you would\n"
            "get an empty node list." % (current, user_config)
        )
    else:
        hazard = (
            "sudo kept your HOME, so mitui would write root-owned files into\n"
            "%s and your later non-root runs would fail on them." % current
        )

    print(
        "Refusing to run under sudo.\n\n"
        "%s\n\n"
        "You do not need root for normal use: the proxy listens on a high port\n"
        "and everything lives in your home directory. For TUN mode, give the\n"
        "*core* the capabilities it needs and keep running mitui as yourself:\n\n"
        "    sudo setcap cap_net_admin,cap_net_bind_service=+ep \\\n"
        "        \"$(command -v mihomo)\"\n"
        "    mitui\n\n"
        "If you really do want to run as root, pass --allow-root."
        % hazard,
        file=sys.stderr,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mitui",
        description="Terminal UI proxy client powered by the mihomo core.",
    )
    p.add_argument("-V", "--version", action="version",
                   version="mitui %s" % __version__)
    p.add_argument("--allow-root", action="store_true",
                   help="proceed even when started with sudo (see the warning)")
    p.set_defaults(func=cmd_tui)
    sp = p.add_subparsers(dest="cmd", metavar="<command>")

    sp.add_parser("tui", help="open the terminal UI (default)") \
        .set_defaults(func=cmd_tui)

    sub = sp.add_parser("sub", help="manage subscriptions")
    subsp = sub.add_subparsers(dest="action", metavar="<action>", required=True)
    add = subsp.add_parser("add", help="add a subscription URL and fetch it")
    add.add_argument("url")
    add.add_argument("-n", "--name", default="")
    add.set_defaults(func=cmd_sub_add)
    subsp.add_parser("list", help="list subscriptions") \
        .set_defaults(func=cmd_sub_list)
    rm = subsp.add_parser("rm", help="remove a subscription")
    rm.add_argument("name")
    rm.set_defaults(func=cmd_sub_rm)
    upd = subsp.add_parser("update", help="refresh subscriptions")
    upd.add_argument("name", nargs="?", default="")
    upd.set_defaults(func=cmd_sub_update)

    link = sp.add_parser("link", help="add a single share link (trojan://...)")
    link.add_argument("uri")
    link.set_defaults(func=cmd_link)

    nodes = sp.add_parser("nodes", help="list parsed nodes")
    nodes.add_argument("-l", "--long", action="store_true")
    nodes.set_defaults(func=cmd_nodes)

    sp.add_parser("gen", help="(re)generate the mihomo config") \
        .set_defaults(func=cmd_gen)
    sp.add_parser("up", help="start the core in the background") \
        .set_defaults(func=cmd_up)
    sp.add_parser("down", help="stop the core") \
        .set_defaults(func=cmd_down)
    sp.add_parser("restart", help="restart the core") \
        .set_defaults(func=cmd_restart)
    sp.add_parser("status", help="show core status") \
        .set_defaults(func=cmd_status)
    sp.add_parser("env", help="print shell proxy exports") \
        .set_defaults(func=cmd_env)

    use = sp.add_parser("use", help="select a node (or AUTO / DIRECT)")
    use.add_argument("name")
    use.set_defaults(func=cmd_use)

    mode = sp.add_parser("mode", help="set the routing mode")
    mode.add_argument("mode", choices=["rule", "global", "direct"])
    mode.set_defaults(func=cmd_mode)

    test = sp.add_parser("test", help="latency test every node")
    test.add_argument("-n", "--top", type=int, default=0,
                      help="only print the N fastest")
    test.set_defaults(func=cmd_test)

    logs = sp.add_parser("logs", help="show the core log tail")
    logs.add_argument("-n", "--lines", type=int, default=40)
    logs.set_defaults(func=cmd_logs)

    inst = sp.add_parser("install-core", help="download the mihomo binary")
    inst.add_argument("--core-version", default="",
                      help="release tag, e.g. v1.19.2 (default: latest)")
    inst.add_argument("--arch", default="",
                      help="override the detected architecture")
    inst.set_defaults(func=cmd_install)

    geo = sp.add_parser("install-geo",
                        help="download the GeoIP database (needed for CN-direct)")
    geo.add_argument("--url", default="", help="override the download URL")
    geo.add_argument("--direct", action="store_true",
                     help="fetch directly instead of through the running proxy")
    geo.set_defaults(func=cmd_install_geo)

    sp.add_parser("paths", help="show config and data paths") \
        .set_defaults(func=cmd_paths)
    return p


# --------------------------------------------------------------------------- #
def cmd_tui(args) -> int:
    from . import ui

    app = App()
    ui.run(app)
    return 0


def cmd_sub_add(args) -> int:
    app = App()
    sub = app.add_sub(args.url, args.name)
    print("added '%s'" % sub["name"])
    count = app.update_sub(sub)
    print("fetched %d nodes" % count)
    app.write_config()
    print("config: %s" % paths.CORE_CONFIG)
    if app.core.is_running():
        print(app.apply())
    return 0


def cmd_sub_list(args) -> int:
    app = App()
    if not app.st.subs:
        print("no subscriptions (add one: mitui sub add <url>)")
        return 0
    for sub in app.st.subs:
        info = sub.get("info") or {}
        extra = ""
        if info.get("total"):
            used = int(info.get("upload") or 0) + int(info.get("download") or 0)
            extra = "  %s/%s" % (human_bytes(used), human_bytes(int(info["total"])))
        print("%-16s %4d nodes  %-10s%s\n  %s"
              % (sub.get("name"), sub.get("count", 0),
                 ago(sub.get("updated")), extra, sub.get("url")))
    return 0


def cmd_sub_rm(args) -> int:
    app = App()
    if not app.st.remove_sub(args.name):
        print("no such subscription: %s" % args.name, file=sys.stderr)
        return 1
    app.st.save()
    app.reload_nodes()
    app.write_config()
    print("removed %s (%d nodes left)" % (args.name, len(app.nodes)))
    return 0


def cmd_sub_update(args) -> int:
    app = App()
    if not app.st.subs:
        print("no subscriptions", file=sys.stderr)
        return 1
    if args.name:
        sub = app.st.find_sub(args.name)
        if not sub:
            print("no such subscription: %s" % args.name, file=sys.stderr)
            return 1
        print("%s: %d nodes" % (args.name, app.update_sub(sub)))
    else:
        total, failed = app.update_all()
        print("%d nodes total" % total)
        for line in failed:
            print("failed: %s" % line, file=sys.stderr)
    app.write_config()
    if app.core.is_running():
        print(app.apply())
    return 0


def cmd_link(args) -> int:
    app = App()
    node = app.add_link(args.uri)
    print("added %s (%s %s:%s)" % (node["name"], node["type"],
                                   node["server"], node["port"]))
    app.write_config()
    if app.core.is_running():
        print(app.apply())
    return 0


def cmd_nodes(args) -> int:
    app = App()
    if not app.nodes:
        print("no nodes")
        return 0
    for node in app.nodes:
        if args.long:
            bits = ["%s=%s" % (k, v) for k, v in node.items()
                    if k not in ("name", "password", "uuid", "auth-str")]
            print("%s\n  %s" % (node["name"], "  ".join(bits)))
        else:
            print("%-40s %-10s %s:%s" % (node["name"], node["type"],
                                         node["server"], node["port"]))
    print("\n%d nodes" % len(app.nodes))
    return 0


def cmd_gen(args) -> int:
    app = App()
    path = app.write_config()
    print("wrote %s (%d nodes)" % (path, len(app.nodes)))
    try:
        out = app.core.test_config()
        print(out or "config test passed")
    except CoreError as exc:
        # Distinguish "no core installed yet" from "the config is wrong".
        if "not found" in str(exc) or "not an executable" in str(exc):
            print("%s" % exc, file=sys.stderr)
        else:
            print("config test failed:\n%s" % exc, file=sys.stderr)
        return 1
    return 0


def cmd_up(args) -> int:
    app = App()
    if app.core.is_running():
        print("already running (pid %d)" % app.core.pid())
        return 0
    print(app.start_core(detached=True))
    print("proxy: http://127.0.0.1:%s (HTTP + SOCKS5)" % app.st["mixed_port"])
    return 0


def cmd_down(args) -> int:
    app = App()
    print(app.stop_core())
    return 0


def cmd_restart(args) -> int:
    app = App()
    print(app.restart_core(detached=True))
    return 0


def cmd_status(args) -> int:
    app = App()
    running = app.core.is_running()
    print("core:    %s" % ("running (pid %d)" % app.core.pid() if running
                           else "stopped"))
    info = read_pidfile()
    if running and info.get("started"):
        print("uptime:  %s" % ago(info["started"]).replace(" ago", ""))
    print("config:  %s" % paths.CORE_CONFIG)
    print("nodes:   %d" % len(app.nodes))
    print("mode:    %s" % app.st["mode"])
    print("port:    %s (mixed HTTP/SOCKS)" % app.st["mixed_port"])
    if not running:
        return 0
    try:
        version = app.api().version()
        print("version: %s" % version.get("version", "?"))
        proxies = app.api().proxies()
        group = proxies.get(PROXY_GROUP) or {}
        print("node:    %s" % (group.get("now") or "-"))
        conns = app.api().connections()
        print("traffic: up %s / down %s   %d connection(s)"
              % (human_bytes(int(conns.get("uploadTotal") or 0)),
                 human_bytes(int(conns.get("downloadTotal") or 0)),
                 len(conns.get("connections") or [])))
    except ApiError as exc:
        print("api:     unreachable (%s)" % exc)
    return 0


def cmd_env(args) -> int:
    app = App()
    url = "http://127.0.0.1:%s" % app.st["mixed_port"]
    print("export http_proxy=%s https_proxy=%s all_proxy=socks5h://127.0.0.1:%s"
          % (url, url, app.st["mixed_port"]))
    print("export no_proxy=localhost,127.0.0.1,::1,10.0.0.0/8,"
          "172.16.0.0/12,192.168.0.0/16")
    return 0


def cmd_use(args) -> int:
    app = App()
    name = args.name
    if name.upper() in ("AUTO", "DIRECT", "REJECT"):
        name = AUTO_GROUP if name.upper() == "AUTO" else name.upper()
    elif not app.node_by_name(name):
        matches = [n["name"] for n in app.nodes if name.lower() in n["name"].lower()]
        if len(matches) == 1:
            name = matches[0]
        elif not matches:
            print("no node matching '%s'" % args.name, file=sys.stderr)
            return 1
        else:
            print("ambiguous, %d matches:" % len(matches), file=sys.stderr)
            for m in matches[:20]:
                print("  %s" % m, file=sys.stderr)
            return 1
    print(app.select(name))
    return 0


def cmd_mode(args) -> int:
    app = App()
    print(app.set_mode(args.mode))
    return 0


def cmd_test(args) -> int:
    app = App()
    if not app.core.is_running():
        print("core is not running (start it with: mitui up)", file=sys.stderr)
        return 1
    tested, failed = app.test_all()
    rows = sorted(
        ((app.delays.get(n["name"]), n["name"]) for n in app.nodes),
        key=lambda r: (r[0] is None, r[0] is not None and r[0] <= 0,
                       r[0] if isinstance(r[0], int) and r[0] > 0 else 0),
    )
    if args.top:
        rows = rows[:args.top]
    for delay, name in rows:
        if delay is None:
            shown = "-"
        elif delay <= 0:
            shown = "timeout"
        else:
            shown = "%d ms" % delay
        print("%-9s %s" % (shown, name))
    print("\ntested %d, %d unreachable" % (tested, failed))
    return 0


def cmd_logs(args) -> int:
    for line in log_tail(args.lines):
        print(line)
    return 0


def cmd_install(args) -> int:
    path = install_core(version=args.core_version, arch=args.arch)
    app = App()
    app.st["mihomo_path"] = path
    app.st.save()
    return 0


def cmd_install_geo(args) -> int:
    app = App()
    if not args.direct and not app.core.is_running():
        print("note: the core is not running, so this fetch goes out directly. "
              "If it fails, start the core first (mitui up) and retry -- the "
              "download then goes through your own proxy.")
    app.install_geo(url=args.url, direct=args.direct)
    if app.st["cn_direct"]:
        print("CN-direct routing is active (GEOIP,CN,DIRECT is back in the rules)")
    else:
        print("installed. Enable 'Route CN traffic direct' in settings to use it.")
    return 0


def cmd_paths(args) -> int:
    print("settings: %s" % paths.SETTINGS_FILE)
    print("config:   %s" % paths.CORE_CONFIG)
    print("core dir: %s" % paths.CORE_HOME)
    print("log:      %s" % paths.LOG_FILE)
    print("pidfile:  %s" % paths.PID_FILE)
    print("binaries: %s" % paths.BIN_DIR)
    return 0
