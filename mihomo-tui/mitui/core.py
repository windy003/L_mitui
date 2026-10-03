"""Locate, install, and supervise the mihomo core process."""

from __future__ import annotations

import gzip
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import time
import urllib.request
from collections import deque
from pathlib import Path

from . import paths
from .api import Api
from .settings import Settings

BINARY_NAMES = ("mihomo", "clash-meta", "Clash.Meta", "clash.meta")
GITHUB_LATEST = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
GITHUB_DL = "https://github.com/MetaCubeX/mihomo/releases/download"
FALLBACK_VERSION = "v1.19.2"

ARCH_MAP = {
    "x86_64": "amd64", "amd64": "amd64",
    "aarch64": "arm64", "arm64": "arm64",
    "armv7l": "armv7", "armv7": "armv7", "armv6l": "armv6",
    "i386": "386", "i686": "386",
    "riscv64": "riscv64",
    "loongarch64": "loong64",
    "mips64": "mips64", "s390x": "s390x",
}


class CoreError(Exception):
    pass


# --------------------------------------------------------------------------- #
# binary discovery / install
# --------------------------------------------------------------------------- #
def find_binary(st: Settings | None = None) -> str:
    if st and st["mihomo_path"]:
        candidate = Path(str(st["mihomo_path"])).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        raise CoreError("mihomo_path is not an executable file: %s" % candidate)
    local = paths.BIN_DIR / "mihomo"
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    for name in BINARY_NAMES:
        found = shutil.which(name)
        if found:
            return found
    raise CoreError(
        "mihomo not found. Install it with your package manager, drop the "
        "binary at %s, or set mihomo_path in settings." % local
    )


def detect_arch() -> str:
    machine = platform.machine().lower()
    arch = ARCH_MAP.get(machine)
    if not arch:
        raise CoreError("unsupported CPU architecture: %s" % machine)
    return arch


def install_core(version: str = "", arch: str = "", log=print) -> str:
    """Download a mihomo release into ~/.local/share/mitui/bin/mihomo."""
    paths.ensure_dirs()
    arch = arch or detect_arch()
    url = ""
    if not version:
        try:
            req = urllib.request.Request(
                GITHUB_LATEST, headers={"User-Agent": "mitui", "Accept": "application/vnd.github+json"}
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                release = json.loads(resp.read().decode())
            version = release.get("tag_name") or FALLBACK_VERSION
            pattern = re.compile(r"^mihomo-linux-%s-v[\d.]+\.gz$" % re.escape(arch))
            for asset in release.get("assets") or []:
                if pattern.match(asset.get("name", "")):
                    url = asset.get("browser_download_url", "")
                    break
        except Exception as exc:
            log("could not query GitHub (%s), falling back to %s"
                % (exc, FALLBACK_VERSION))
            version = FALLBACK_VERSION
    if not url:
        url = "%s/%s/mihomo-linux-%s-%s.gz" % (GITHUB_DL, version, arch, version)

    log("downloading %s" % url)
    target = paths.BIN_DIR / "mihomo"
    tmp = paths.BIN_DIR / "mihomo.download"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "mitui"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            blob = resp.read()
    except Exception as exc:
        raise CoreError("download failed: %s" % exc) from exc
    try:
        binary = gzip.decompress(blob)
    except OSError as exc:
        raise CoreError("downloaded file is not gzip: %s" % exc) from exc
    tmp.write_bytes(binary)
    tmp.chmod(0o755)
    os.replace(tmp, target)
    log("installed %s (%s, %.1f MiB)" % (target, version, len(binary) / 1048576))
    return str(target)


GEO_MMDB_URLS = (
    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/geoip.metadb",
)
# every MaxMind DB file carries this marker before its metadata section
MMDB_MAGIC = b"\xab\xcd\xefMaxMind.com"


def install_geo(url: str = "", via_proxy: str = "", log=print) -> str:
    """Download the GeoIP database into the core directory.

    mihomo blocks on this download itself at startup, which deadlocks when the
    only working route out is the proxy it has not started yet. Fetching it
    here -- optionally *through* an already running proxy -- breaks the cycle.
    """
    paths.ensure_dirs()
    candidates = [url] if url else list(GEO_MMDB_URLS)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(
            {"http": via_proxy, "https": via_proxy} if via_proxy else {}
        )
    )
    target = paths.CORE_HOME / "geoip.metadb"
    errors = []
    for candidate in candidates:
        log("downloading %s%s"
            % (candidate, " via %s" % via_proxy if via_proxy else ""))
        try:
            req = urllib.request.Request(candidate,
                                         headers={"User-Agent": "mitui"})
            with opener.open(req, timeout=120) as resp:
                blob = resp.read()
        except Exception as exc:
            errors.append("%s: %s" % (candidate, exc))
            continue
        if MMDB_MAGIC not in blob[-4096:] and MMDB_MAGIC not in blob:
            errors.append("%s: not a MaxMind database (%d bytes)"
                          % (candidate, len(blob)))
            continue
        tmp = target.with_suffix(".download")
        tmp.write_bytes(blob)
        os.replace(tmp, target)
        log("installed %s (%.1f MiB)" % (target, len(blob) / 1048576))
        return str(target)
    raise CoreError("could not download the GeoIP database:\n  "
                    + "\n  ".join(errors))


# --------------------------------------------------------------------------- #
# process supervision
# --------------------------------------------------------------------------- #
class Core:
    """Owns the mihomo child process and the pidfile that tracks it."""

    def __init__(self, st: Settings) -> None:
        self.st = st
        self.proc: subprocess.Popen | None = None
        self.logs: deque = deque(maxlen=2000)

    # state ---------------------------------------------------------------- #
    def pid(self) -> int:
        if self.proc and self.proc.poll() is None:
            return self.proc.pid
        info = read_pidfile()
        return int(info.get("pid", 0)) if info else 0

    def is_running(self) -> bool:
        if self.proc is not None:
            return self.proc.poll() is None
        info = read_pidfile()
        if not info:
            return False
        if pid_alive(int(info.get("pid", 0))):
            return True
        clear_pidfile()
        return False

    def owns_process(self) -> bool:
        """True when this TUI started the core (so quitting should stop it)."""
        return self.proc is not None and self.proc.poll() is None

    def api(self) -> Api:
        return Api(str(self.st["controller"]), str(self.st["secret"]))

    # lifecycle ------------------------------------------------------------ #
    def test_config(self, config: str = "") -> str:
        """Run 'mihomo -t'. Returns the output; raises CoreError on failure."""
        binary = find_binary(self.st)
        cfg = config or str(paths.CORE_CONFIG)
        try:
            res = subprocess.run(
                [binary, "-t", "-d", str(paths.CORE_HOME), "-f", cfg],
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            # Keep whatever the core managed to print: a hang here is almost
            # always a blocking geo database download, and the log says so.
            partial = "".join(part for part in (exc.stdout, exc.stderr)
                              if isinstance(part, str)).strip()
            raise CoreError(
                "config test timed out after 30s%s"
                % (":\n" + partial[-600:] if partial else "")
            ) from exc
        except OSError as exc:
            raise CoreError("cannot execute %s: %s" % (binary, exc)) from exc
        out = (res.stdout + res.stderr).strip()
        if res.returncode != 0:
            raise CoreError(out or "config test failed")
        return out

    def preflight(self, require_config: bool = True) -> str:
        """Everything that must hold before a start can succeed.

        Callable on its own so a restart can fail *before* taking the running
        core down, instead of leaving the user with no proxy at all. Pass
        require_config=False to run the checks before the config is written.
        """
        binary = find_binary(self.st)
        if require_config and not paths.CORE_CONFIG.exists():
            raise CoreError("no config yet -- generate one first")
        if self.st["tun"] and not tun_ready(self.st):
            raise CoreError(
                "TUN mode needs privileges. Either grant the core the "
                "capabilities it needs:\n"
                "  sudo setcap cap_net_admin,cap_net_bind_service=+ep %s\n"
                "or turn TUN off in the settings tab." % binary
            )
        return binary

    def start(self, detached: bool = False, wait: float = 10.0) -> int:
        if self.is_running():
            raise CoreError("core is already running (pid %d)" % self.pid())
        binary = self.preflight()
        paths.ensure_dirs()

        argv = [binary, "-d", str(paths.CORE_HOME), "-f", str(paths.CORE_CONFIG)]
        logfh = open(paths.LOG_FILE, "ab", buffering=0)
        logfh.write(("\n=== mitui start %s ===\n"
                     % time.strftime("%Y-%m-%d %H:%M:%S")).encode())
        try:
            proc = subprocess.Popen(
                argv, stdout=logfh, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, start_new_session=True,
                cwd=str(paths.CORE_HOME),
            )
        except OSError as exc:
            logfh.close()
            raise CoreError("failed to launch %s: %s" % (binary, exc)) from exc
        finally:
            try:
                logfh.close()
            except OSError:
                pass

        write_pidfile({
            "pid": proc.pid, "started": time.time(), "detached": detached,
            "binary": binary, "config": str(paths.CORE_CONFIG),
        })
        self.proc = None if detached else proc

        api = self.api()
        deadline = time.time() + wait
        while time.time() < deadline:
            if proc.poll() is not None:
                clear_pidfile()
                self.proc = None
                raise CoreError(
                    "core exited immediately (code %s):\n%s"
                    % (proc.returncode, "\n".join(log_tail(15)))
                )
            if api.alive():
                return proc.pid
            time.sleep(0.25)
        # Process is up but the controller never answered; leave it running and
        # let the caller decide -- the log usually explains why.
        raise CoreError(
            "core started (pid %d) but the API did not respond on %s:\n%s"
            % (proc.pid, self.st["controller"], "\n".join(log_tail(10)))
        )

    def stop(self, timeout: float = 6.0) -> bool:
        pid = self.pid()
        if not pid:
            self.proc = None
            clear_pidfile()
            return False
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            clear_pidfile()
            self.proc = None
            return False
        except PermissionError as exc:
            raise CoreError("not allowed to stop pid %d: %s" % (pid, exc)) from exc
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not pid_alive(pid):
                break
            time.sleep(0.15)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        if self.proc is not None:
            try:
                self.proc.wait(timeout=1)
            except Exception:
                pass
        self.proc = None
        clear_pidfile()
        return True

    def restart(self) -> int:
        if self.is_running():
            self.stop()
        return self.start()


def tun_ready(st: Settings | None = None) -> bool:
    """True when the core may create a TUN device (root, or CAP_NET_ADMIN)."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    try:
        binary = find_binary(st)
    except CoreError:
        return False
    return _has_net_admin(binary)


def _has_net_admin(binary: str) -> bool:
    getcap = shutil.which("getcap")
    if not getcap:
        return False
    try:
        res = subprocess.run([getcap, binary], capture_output=True, text=True,
                             timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return "cap_net_admin" in res.stdout


# --------------------------------------------------------------------------- #
# pidfile + log helpers
# --------------------------------------------------------------------------- #
def read_pidfile() -> dict:
    try:
        with open(paths.PID_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write_pidfile(info: dict) -> None:
    paths.ensure_dirs()
    with open(paths.PID_FILE, "w", encoding="utf-8") as fh:
        json.dump(info, fh)


def clear_pidfile() -> None:
    try:
        os.unlink(paths.PID_FILE)
    except OSError:
        pass


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # Guard against pid reuse: the command line must still look like the core.
    cmdline = Path("/proc/%d/cmdline" % pid)
    if cmdline.exists():
        try:
            raw = cmdline.read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            return True
        return any(name.lower() in raw.lower() for name in BINARY_NAMES)
    return True


def log_tail(n: int = 40) -> list:
    try:
        with open(paths.LOG_FILE, "rb") as fh:
            try:
                fh.seek(max(0, os.path.getsize(paths.LOG_FILE) - 64 * 1024))
            except OSError:
                pass
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    return [ln.rstrip() for ln in lines[-n:]]
