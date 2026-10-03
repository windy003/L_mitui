"""Command line entry point. It takes no arguments and opens the TUI.

Everything is driven from inside the TUI -- subscriptions are added there
with `n` (a subscription URL) or `L` (a single trojan:// share link).
"""

from __future__ import annotations

import sys

from . import paths
from .api import ApiError
from .app import App
from .core import CoreError
from .subs import SubError


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Keep stdout and stderr interleaved in the right order when the output is
    # piped or redirected (stdout would be block buffered otherwise).
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError):
        pass
    if argv:
        print("mitui takes no arguments: run `mitui` and do everything from "
              "the TUI (press ? for the key list).", file=sys.stderr)
        return 2
    if _is_sudo() and not _root_allowed():
        _warn_sudo()
        return 2
    if sys.platform == "win32":
        print("mitui targets Linux (it supervises the mihomo core and uses "
              "POSIX signals).", file=sys.stderr)
        return 2
    try:
        from . import ui

        ui.run(App())
        return 0
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


def _root_allowed() -> bool:
    """Escape hatch for the sudo refusal, now that there are no CLI flags."""
    import os

    return os.environ.get("MITUI_ALLOW_ROOT", "") not in ("", "0")


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
        "    sudo setcap cap_net_admin,cap_net_bind_service=+ep \\n"
        "        \"$(command -v mihomo)\"\n"
        "    mitui\n\n"
        "If you really do want to run as root, set MITUI_ALLOW_ROOT=1."
        % hazard,
        file=sys.stderr,
    )
