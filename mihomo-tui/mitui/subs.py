"""Subscription fetching and node parsing.

Three payload shapes show up in the wild and all three are handled:

1. a Clash / mihomo YAML config with a ``proxies:`` list
2. a base64 blob that decodes to newline separated share links
3. plain newline separated share links

Everything is normalized into mihomo proxy dicts, i.e. exactly what goes under
``proxies:`` in the generated config.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.error
import urllib.parse as up
import urllib.request
from typing import Any

from . import yamlio

DEFAULT_UA = "clash.meta/1.19.0"
FETCH_TIMEOUT = 20

# Proxy types mihomo understands; anything else in a YAML sub is dropped so the
# core never fails to start because of one exotic node.
KNOWN_TYPES = {
    "trojan", "ss", "ssr", "vmess", "vless", "hysteria", "hysteria2",
    "tuic", "snell", "socks5", "http", "wireguard", "anytls", "mieru", "ssh",
}


class SubError(Exception):
    pass


# --------------------------------------------------------------------------- #
# fetching
# --------------------------------------------------------------------------- #
def fetch(url: str, ua: str = DEFAULT_UA, timeout: int = FETCH_TIMEOUT,
          proxy: str = "") -> tuple:
    """Download a subscription. Returns ``(text, info)``.

    ``info`` carries the provider metadata some panels send back, parsed out of
    the ``subscription-userinfo`` / ``profile-*`` headers.
    """
    url = url.strip()
    if url.startswith("file://"):
        path = up.urlsplit(url).path
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(), {}
    if not re.match(r"^https?://", url):
        raise SubError("unsupported URL scheme: %s" % url[:32])

    req = urllib.request.Request(url, headers={
        "User-Agent": ua,
        "Accept": "*/*",
    })
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        # An explicit empty mapping disables proxy pickup from the environment:
        # fetching through the proxy we are about to configure would deadlock.
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

    text = raw.decode("utf-8", "replace")
    return text, _sub_info(headers)


def _sub_info(headers: dict) -> dict:
    low = {k.lower(): v for k, v in headers.items()}
    info: dict = {}
    raw = low.get("subscription-userinfo", "")
    for part in raw.split(";"):
        key, _, val = part.strip().partition("=")
        key = key.strip()
        val = val.strip()
        if not key or not val:
            continue
        try:
            info[key] = int(val)
        except ValueError:
            info[key] = val
    name = low.get("content-disposition", "")
    match = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", name)
    if match:
        info["filename"] = up.unquote(match.group(1))
    if low.get("profile-update-interval"):
        info["update-interval"] = low["profile-update-interval"]
    return info


# --------------------------------------------------------------------------- #
# top level parsing
# --------------------------------------------------------------------------- #
def parse(text: str) -> list:
    """Parse any supported subscription payload into mihomo proxy dicts."""
    text = text.strip()
    if not text:
        return []

    if "proxies" in text[:4096] and re.search(r"^\s*proxies\s*:", text, re.M):
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
        if not line or line.startswith("#") or line.startswith("//"):
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
    if not isinstance(data, dict):
        return []
    raw = data.get("proxies")
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        node = _clean_yaml_node(item)
        if node:
            out.append(node)
    return out


def _clean_yaml_node(item: Any) -> dict | None:
    if not isinstance(item, dict):
        return None
    ptype = str(item.get("type", "")).lower()
    if ptype not in KNOWN_TYPES:
        return None
    name = item.get("name")
    server = item.get("server")
    port = item.get("port")
    if ptype != "wireguard" and (not name or not server or port in (None, "")):
        return None
    node = {k: v for k, v in item.items() if v is not None}
    node["name"] = str(name).strip() or "%s:%s" % (server, port)
    node["type"] = ptype
    try:
        node["port"] = int(port)
    except (TypeError, ValueError):
        return None
    # Providers sometimes ship alpn as a comma joined string.
    if isinstance(node.get("alpn"), str):
        node["alpn"] = [x.strip() for x in node["alpn"].split(",") if x.strip()]
    return node


def dedupe(nodes: list) -> list:
    """Make names unique -- mihomo rejects a config with duplicate proxy names."""
    seen: dict = {}
    out = []
    for node in nodes:
        base = node.get("name") or "node"
        base = re.sub(r"\s+", " ", str(base)).strip() or "node"
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


# --------------------------------------------------------------------------- #
# share link parsing
# --------------------------------------------------------------------------- #
def parse_uri(uri: str) -> dict | None:
    scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
    handler = {
        "trojan": _trojan,
        "trojan-go": _trojan,
        "ss": _ss,
        "vmess": _vmess,
        "vless": _vless,
        "hysteria2": _hysteria2,
        "hy2": _hysteria2,
        "hysteria": _hysteria1,
        "hy": _hysteria1,
        "socks": _socks,
        "socks5": _socks,
        "http": None,
        "https": None,
    }.get(scheme)
    if handler is None:
        return None
    try:
        return handler(uri)
    except Exception:
        return None


def _q(query: str) -> dict:
    out = {}
    for key, val in up.parse_qsl(query, keep_blank_values=True):
        out[key.lower()] = val
    return out


def _truthy(val: str) -> bool:
    return str(val).lower() in ("1", "true", "yes", "on")


def _name_of(frag: str, host: str, port: Any) -> str:
    name = up.unquote(frag or "").strip()
    return name or "%s:%s" % (host, port)


def _tls_common(node: dict, q: dict, sni_default: str = "") -> None:
    """Shared TLS-ish query parameters for trojan / vless / vmess links."""
    sni = q.get("sni") or q.get("peer") or q.get("servername") or sni_default
    if sni:
        node["sni"] = sni
    if _truthy(q.get("allowinsecure", "")) or _truthy(q.get("insecure", "")) \
            or _truthy(q.get("skip-cert-verify", "")):
        node["skip-cert-verify"] = True
    alpn = q.get("alpn", "")
    if alpn:
        values = [x.strip() for x in up.unquote(alpn).split(",") if x.strip()]
        if values:
            node["alpn"] = values
    fp = q.get("fp") or q.get("client-fingerprint")
    if fp and fp != "none":
        node["client-fingerprint"] = fp


def _transport(node: dict, q: dict) -> None:
    """Map the ``type=`` transport parameter onto mihomo network options."""
    net = (q.get("type") or q.get("network") or "tcp").lower()
    if net in ("ws", "websocket"):
        node["network"] = "ws"
        opts: dict = {"path": up.unquote(q.get("path", "/")) or "/"}
        host = q.get("host") or node.get("sni")
        if host:
            opts["headers"] = {"Host": host}
        if q.get("ed"):
            try:
                opts["max-early-data"] = int(q["ed"])
                opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
            except ValueError:
                pass
        node["ws-opts"] = opts
    elif net == "grpc":
        node["network"] = "grpc"
        service = q.get("servicename") or q.get("grpc-service-name") or ""
        node["grpc-opts"] = {"grpc-service-name": up.unquote(service)}
    elif net in ("h2", "http"):
        node["network"] = "h2" if net == "h2" else "http"
        opts = {}
        if q.get("path"):
            opts["path"] = [up.unquote(q["path"])] if net == "h2" \
                else [up.unquote(q["path"])]
        host = q.get("host")
        if host:
            opts["host"] = [h.strip() for h in host.split(",") if h.strip()]
        if opts:
            node["%s-opts" % node["network"]] = opts
    elif net in ("tcp", "", "none", "raw"):
        pass
    else:
        node["network"] = net


def _trojan(uri: str) -> dict | None:
    parts = up.urlsplit(uri)
    host = parts.hostname
    if not host:
        return None
    port = parts.port or 443
    password = up.unquote(parts.username or "")
    if parts.password:  # pwd written as user:pass@
        password = "%s:%s" % (password, up.unquote(parts.password))
    q = _q(parts.query)
    node = {
        "name": _name_of(parts.fragment, host, port),
        "type": "trojan",
        "server": host,
        "port": port,
        "password": password,
        "udp": True,
    }
    _tls_common(node, q, sni_default=q.get("host", ""))
    _transport(node, q)
    flow = q.get("flow")
    if flow:
        node["flow"] = flow
    return node


def _ss(uri: str) -> dict | None:
    raw = uri[len("ss://"):]
    frag = ""
    if "#" in raw:
        raw, frag = raw.split("#", 1)
    query = ""
    if "?" in raw:
        raw, query = raw.split("?", 1)
    q = _q(query)

    if "@" in raw:
        userinfo, hostport = raw.rsplit("@", 1)
        decoded = b64decode(userinfo)
        if decoded and ":" in decoded:
            userinfo = decoded
        else:
            userinfo = up.unquote(userinfo)
    else:
        decoded = b64decode(raw)
        if not decoded or "@" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)

    method, _, password = userinfo.partition(":")
    host, _, port_s = hostport.rpartition(":")
    host = host.strip("[]")
    if not host or not port_s.isdigit():
        return None
    port = int(port_s)
    node = {
        "name": _name_of(frag, host, port),
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method or "aes-128-gcm",
        "password": password,
        "udp": True,
    }
    plugin = up.unquote(q.get("plugin", ""))
    if plugin:
        bits = plugin.split(";")
        pname = bits[0]
        popts = {}
        for item in bits[1:]:
            key, _, val = item.partition("=")
            popts[key.strip()] = val.strip()
        if pname in ("obfs-local", "simple-obfs", "obfs"):
            node["plugin"] = "obfs"
            node["plugin-opts"] = {
                "mode": popts.get("obfs", "http"),
                "host": popts.get("obfs-host", ""),
            }
        elif pname.startswith("v2ray"):
            node["plugin"] = "v2ray-plugin"
            opts = {
                "mode": popts.get("mode", "websocket"),
                "path": popts.get("path", "/"),
                "host": popts.get("host", ""),
            }
            if "tls" in popts:
                opts["tls"] = True
            node["plugin-opts"] = opts
        elif pname.startswith("shadow-tls"):
            node["plugin"] = "shadow-tls"
            node["plugin-opts"] = {
                "host": popts.get("host", ""),
                "password": popts.get("password", ""),
                "version": int(popts.get("version", "2") or 2),
            }
    return node


def _vmess(uri: str) -> dict | None:
    body = uri[len("vmess://"):]
    decoded = b64decode(body)
    if not decoded:
        return None
    try:
        j = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    if not isinstance(j, dict):
        return None
    host = str(j.get("add", "")).strip()
    port_raw = j.get("port", 443)
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return None
    if not host:
        return None
    node = {
        "name": str(j.get("ps") or "").strip() or "%s:%s" % (host, port),
        "type": "vmess",
        "server": host,
        "port": port,
        "uuid": str(j.get("id", "")),
        "alterId": int(j.get("aid", j.get("alterId", 0)) or 0),
        "cipher": str(j.get("scy") or j.get("security") or "auto"),
        "udp": True,
    }
    if str(j.get("tls", "")).lower() in ("tls", "true", "1", "reality"):
        node["tls"] = True
    q = {
        "type": str(j.get("net", "tcp")),
        "host": str(j.get("host", "")),
        "path": str(j.get("path", "/")),
        "sni": str(j.get("sni", "")),
        "alpn": str(j.get("alpn", "")),
        "fp": str(j.get("fp", "")),
        "servicename": str(j.get("path", "")) if j.get("net") == "grpc" else "",
        "insecure": str(j.get("allowInsecure", j.get("skip-cert-verify", ""))),
    }
    _tls_common(node, q, sni_default=q["host"])
    _transport(node, q)
    return node


def _vless(uri: str) -> dict | None:
    parts = up.urlsplit(uri)
    host = parts.hostname
    if not host:
        return None
    port = parts.port or 443
    q = _q(parts.query)
    node = {
        "name": _name_of(parts.fragment, host, port),
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": up.unquote(parts.username or ""),
        "udp": True,
    }
    security = (q.get("security") or "none").lower()
    if security in ("tls", "xtls", "reality"):
        node["tls"] = True
    if security == "reality":
        node["reality-opts"] = {
            "public-key": q.get("pbk", ""),
            "short-id": q.get("sid", ""),
        }
    flow = q.get("flow")
    if flow:
        node["flow"] = flow
    encryption = q.get("encryption")
    if encryption and encryption != "none":
        node["encryption"] = encryption
    _tls_common(node, q, sni_default=q.get("host", ""))
    _transport(node, q)
    return node


def _hysteria2(uri: str) -> dict | None:
    parts = up.urlsplit(uri)
    host = parts.hostname
    if not host:
        return None
    port = parts.port or 443
    auth = up.unquote(parts.username or "")
    if parts.password:
        auth = "%s:%s" % (auth, up.unquote(parts.password))
    q = _q(parts.query)
    node = {
        "name": _name_of(parts.fragment, host, port),
        "type": "hysteria2",
        "server": host,
        "port": port,
        "password": auth,
    }
    if q.get("sni"):
        node["sni"] = q["sni"]
    if _truthy(q.get("insecure", "")) or _truthy(q.get("allowinsecure", "")):
        node["skip-cert-verify"] = True
    if q.get("obfs"):
        node["obfs"] = q["obfs"]
        pwd = q.get("obfs-password") or q.get("obfs_password")
        if pwd:
            node["obfs-password"] = pwd
    if q.get("pinsha256"):
        node["fingerprint"] = q["pinsha256"]
    if q.get("up"):
        node["up"] = q["up"]
    if q.get("down"):
        node["down"] = q["down"]
    return node


def _hysteria1(uri: str) -> dict | None:
    parts = up.urlsplit(uri)
    host = parts.hostname
    if not host:
        return None
    port = parts.port or 443
    q = _q(parts.query)
    node = {
        "name": _name_of(parts.fragment, host, port),
        "type": "hysteria",
        "server": host,
        "port": port,
        "auth-str": q.get("auth", ""),
        "protocol": q.get("protocol", "udp"),
        "up": q.get("upmbps", "50"),
        "down": q.get("downmbps", "100"),
    }
    if q.get("peer") or q.get("sni"):
        node["sni"] = q.get("sni") or q.get("peer")
    if _truthy(q.get("insecure", "")):
        node["skip-cert-verify"] = True
    if q.get("obfs"):
        node["obfs"] = q["obfs"]
    if q.get("alpn"):
        node["alpn"] = [x for x in q["alpn"].split(",") if x]
    return node


def _socks(uri: str) -> dict | None:
    parts = up.urlsplit(uri)
    host = parts.hostname
    if not host:
        return None
    port = parts.port or 1080
    node = {
        "name": _name_of(parts.fragment, host, port),
        "type": "socks5",
        "server": host,
        "port": port,
        "udp": True,
    }
    user = up.unquote(parts.username or "")
    if user and not parts.password:
        decoded = b64decode(user)
        if decoded and ":" in decoded:
            user, _, pwd = decoded.partition(":")
            node["username"] = user
            node["password"] = pwd
            return node
    if user:
        node["username"] = user
    if parts.password:
        node["password"] = up.unquote(parts.password)
    return node


# --------------------------------------------------------------------------- #
# base64 helper
# --------------------------------------------------------------------------- #
def b64decode(data: str) -> str:
    """Lenient base64 decode (url-safe alphabet, missing padding). '' on failure."""
    s = re.sub(r"\s+", "", data.strip())
    if not s:
        return ""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((-len(s)) % 4)
    try:
        return base64.b64decode(s, validate=False).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""
