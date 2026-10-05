"""Fetch subscriptions and parse Trojan share links into mihomo proxies."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.error
import urllib.parse as up
import urllib.request
from typing import Any

from . import yamlio

DEFAULT_UA = "clash.meta/1.19.0"
FETCH_TIMEOUT = 20


class SubError(Exception):
    pass


def fetch(url: str, ua: str = DEFAULT_UA, timeout: int = FETCH_TIMEOUT,
          proxy: str = "") -> tuple:
    """Download a subscription and return its text and provider metadata."""
    url = url.strip()
    if url.startswith("file://"):
        path = up.urlsplit(url).path
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(), {}
    if not re.match(r"^https?://", url):
        raise SubError("unsupported URL scheme: %s" % url[:32])

    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": "*/*"})
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        # Avoid fetching through the proxy that this app is configuring.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            headers = dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        raise SubError("HTTP %s from provider" % exc.code) from exc
    except urllib.error.URLError as exc:
        raise SubError("cannot reach provider: %s" % exc.reason) from exc
    except OSError as exc:
        raise SubError(str(exc)) from exc
    return raw.decode("utf-8", "replace"), _sub_info(headers)


def _sub_info(headers: dict) -> dict:
    low = {k.lower(): v for k, v in headers.items()}
    info: dict = {}
    for part in low.get("subscription-userinfo", "").split(";"):
        key, _, val = part.strip().partition("=")
        if key and val:
            try:
                info[key.strip()] = int(val.strip())
            except ValueError:
                info[key.strip()] = val.strip()
    match = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)",
                      low.get("content-disposition", ""))
    if match:
        info["filename"] = up.unquote(match.group(1))
    if low.get("profile-update-interval"):
        info["update-interval"] = low["profile-update-interval"]
    return info


def parse(text: str) -> list:
    """Parse Trojan links from plain, base64, or mihomo YAML subscriptions."""
    text = text.strip()
    if not text:
        return []
    if re.search(r"^\s*proxies\s*:", text[:4096], re.M):
        nodes = _from_yaml(text)
        if nodes:
            return dedupe(nodes)
    body = text
    if "://" not in text[:256]:
        decoded = b64decode(text)
        if decoded and "://" in decoded:
            body = decoded
    nodes = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        node = parse_uri(line)
        if node:
            nodes.append(node)
    return dedupe(nodes)


def _from_yaml(text: str) -> list:
    try:
        data = yamlio.load(text)
    except ValueError:
        return []
    raw = data.get("proxies") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return []
    return [node for item in raw if (node := _clean_yaml_node(item))]


def _clean_yaml_node(item: Any) -> dict | None:
    if not isinstance(item, dict) or str(item.get("type", "")).lower() != "trojan":
        return None
    name, server, port = item.get("name"), item.get("server"), item.get("port")
    if not name or not server or port in (None, ""):
        return None
    node = {k: v for k, v in item.items() if v is not None}
    node.update(name=str(name).strip() or "%s:%s" % (server, port), type="trojan")
    try:
        node["port"] = int(port)
    except (TypeError, ValueError):
        return None
    if isinstance(node.get("alpn"), str):
        node["alpn"] = [x.strip() for x in node["alpn"].split(",") if x.strip()]
    return node


def dedupe(nodes: list) -> list:
    """Make names unique -- mihomo rejects a config with duplicate proxy names."""
    seen: dict = {}
    out = []
    for node in nodes:
        base = re.sub(r"\s+", " ", str(node.get("name") or "node")).strip() or "node"
        name = base
        if name in seen:
            seen[base] += 1
            name = "%s #%d" % (base, seen[base])
            while name in seen:
                seen[base] += 1
                name = "%s #%d" % (base, seen[base])
        seen[name] = seen.get(name, 1)
        node["name"] = name
        out.append(node)
    return out


def parse_uri(uri: str) -> dict | None:
    """Parse one trojan:// share link; every other scheme is unsupported."""
    if "://" not in uri or uri.split("://", 1)[0].lower() != "trojan":
        return None
    try:
        parts = up.urlsplit(uri)
        host = parts.hostname
        if not host:
            return None
        port = parts.port or 443
        password = up.unquote(parts.username or "")
        if parts.password:
            password += ":" + up.unquote(parts.password)
        q = {key.lower(): val for key, val in
             up.parse_qsl(parts.query, keep_blank_values=True)}
        node = {
            "name": up.unquote(parts.fragment).strip() or "%s:%s" % (host, port),
            "type": "trojan", "server": host, "port": port,
            "password": password, "udp": True,
        }
        sni = q.get("sni") or q.get("peer") or q.get("servername") or q.get("host")
        if sni:
            node["sni"] = sni
        if any(q.get(key, "").lower() in ("1", "true", "yes", "on")
               for key in ("allowinsecure", "insecure", "skip-cert-verify")):
            node["skip-cert-verify"] = True
        alpn = [part.strip() for part in up.unquote(q.get("alpn", "")).split(",")
                if part.strip()]
        if alpn:
            node["alpn"] = alpn
        fp = q.get("fp") or q.get("client-fingerprint")
        if fp and fp != "none":
            node["client-fingerprint"] = fp
        net = (q.get("type") or q.get("network") or "tcp").lower()
        if net in ("ws", "websocket"):
            node["network"] = "ws"
            opts: dict = {"path": up.unquote(q.get("path", "/")) or "/"}
            host_header = q.get("host") or node.get("sni")
            if host_header:
                opts["headers"] = {"Host": host_header}
            if q.get("ed", "").isdigit():
                opts["max-early-data"] = int(q["ed"])
                opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
            node["ws-opts"] = opts
        elif net == "grpc":
            node["network"] = "grpc"
            service = q.get("servicename") or q.get("grpc-service-name") or ""
            node["grpc-opts"] = {"grpc-service-name": up.unquote(service)}
        elif net in ("h2", "http"):
            node["network"] = net
            opts = {}
            if q.get("path"):
                opts["path"] = [up.unquote(q["path"])]
            if q.get("host"):
                opts["host"] = [v.strip() for v in q["host"].split(",") if v.strip()]
            if opts:
                node["%s-opts" % net] = opts
        elif net not in ("tcp", "", "none", "raw"):
            node["network"] = net
        if q.get("flow"):
            node["flow"] = q["flow"]
        return node
    except (ValueError, UnicodeError):
        return None


def b64decode(data: str) -> str:
    """Lenient base64 decode (url-safe alphabet, missing padding). '' on failure."""
    s = re.sub(r"\s+", "", data.strip()).replace("-", "+").replace("_", "/")
    if not s:
        return ""
    s += "=" * ((-len(s)) % 4)
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""
