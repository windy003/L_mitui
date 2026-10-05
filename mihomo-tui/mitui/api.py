"""Client for the mihomo external controller (RESTful API)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse as up
import urllib.request
from typing import Any, Iterator


class ApiError(Exception):
    pass


class Api:
    def __init__(self, controller: str, secret: str = "") -> None:
        host = controller.strip()
        if host.startswith("http://") or host.startswith("https://"):
            self.base = host.rstrip("/")
        else:
            if host.startswith(":"):
                host = "127.0.0.1" + host
            self.base = "http://%s" % host.rstrip("/")
        self.secret = secret
        # 控制平面调用绝不通过代理路由，包括核心程序自身提供的代理。
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({})
        )

    # low level ------------------------------------------------------------ #
    def _request(self, method: str, path: str, body: Any = None,
                 timeout: float = 5.0):
        url = self.base + path
        data = None
        headers = {"Accept": "application/json"}
        if self.secret:
            headers["Authorization"] = "Bearer %s" % self.secret
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            return self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read().decode()).get("message", "")
            except Exception:
                pass
            raise ApiError("HTTP %d %s" % (exc.code, detail or exc.reason)) from exc
        except urllib.error.URLError as exc:
            raise ApiError(str(exc.reason)) from exc
        except OSError as exc:
            raise ApiError(str(exc)) from exc

    def _json(self, method: str, path: str, body: Any = None,
              timeout: float = 5.0) -> Any:
        with self._request(method, path, body, timeout) as resp:
            raw = resp.read()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            raise ApiError("bad JSON from core") from exc

    # endpoints ------------------------------------------------------------ #
    def version(self) -> dict:
        return self._json("GET", "/version", timeout=2.0)

    def alive(self) -> bool:
        try:
            self.version()
            return True
        except ApiError:
            return False

    def proxies(self) -> dict:
        data = self._json("GET", "/proxies")
        out = data.get("proxies") if isinstance(data, dict) else None
        return out if isinstance(out, dict) else {}

    def configs(self) -> dict:
        data = self._json("GET", "/configs")
        return data if isinstance(data, dict) else {}

    def set_mode(self, mode: str) -> None:
        self._json("PATCH", "/configs", {"mode": mode})

    def reload(self, config_path: str, force: bool = True) -> None:
        path = "/configs?force=%s" % ("true" if force else "false")
        self._json("PUT", path, {"path": config_path}, timeout=20.0)

    def select(self, group: str, name: str) -> None:
        self._json("PUT", "/proxies/%s" % up.quote(group, safe=""),
                   {"name": name})

    def delay(self, name: str, url: str, timeout_ms: int = 3000) -> int:
        query = up.urlencode({"timeout": timeout_ms, "url": url})
        data = self._json(
            "GET",
            "/proxies/%s/delay?%s" % (up.quote(name, safe=""), query),
            timeout=timeout_ms / 1000.0 + 3.0,
        )
        value = data.get("delay") if isinstance(data, dict) else None
        if not isinstance(value, int):
            raise ApiError("timeout")
        return value

    def group_delay(self, group: str, url: str, timeout_ms: int = 3000) -> dict:
        """Test every member of a group in one call. {name: delay_ms}."""
        query = up.urlencode({"timeout": timeout_ms, "url": url})
        data = self._json(
            "GET",
            "/group/%s/delay?%s" % (up.quote(group, safe=""), query),
            timeout=timeout_ms / 1000.0 + 25.0,
        )
        return data if isinstance(data, dict) else {}

    def connections(self) -> dict:
        data = self._json("GET", "/connections")
        return data if isinstance(data, dict) else {}

    def close_connections(self) -> None:
        self._json("DELETE", "/connections")

    # streams -------------------------------------------------------------- #
    def stream(self, path: str) -> Iterator[dict]:
        """Yield JSON objects from a chunked endpoint (/traffic, /logs, ...)."""
        with self._request("GET", path, timeout=None) as resp:
            for raw in resp:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw.decode("utf-8", "replace"))
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    yield obj

    def traffic(self) -> Iterator[dict]:
        return self.stream("/traffic")

    def logs(self, level: str = "info") -> Iterator[dict]:
        return self.stream("/logs?level=%s" % up.quote(level))
