"""Render a mihomo config.yaml from settings + parsed nodes."""

from __future__ import annotations

from . import paths, yamlio
from .settings import AUTO_GROUP, PROXY_GROUP, Settings

# 私有地址段和回环地址始终绕过代理；将其保留为普通规则
# 规则（而非 GEOIP/geosite 规则集）可确保核心程序正常启动，即使
# 尚未下载任何地理位置数据库。

# 规则需要 GeoIP 时，mihomo 会在工作目录中查找以下数据库文件之一。
# 如果文件不存在，启动时就会等待下载。因此只有数据库文件已存在时，才生成
# 地理位置规则（参见 core.py 中的 install_geo）。
MMDB_NAMES = ("geoip.metadb", "Country.mmdb", "GeoLite2-Country.mmdb")

LOCAL_RULES = [
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,localhost,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
]


def build(st: Settings, nodes: list) -> dict:
    """组装配置字典。``nodes`` 是 mihomo 代理配置字典列表。"""
    nodes = _apply_defaults(st, nodes)
    names = [n["name"] for n in nodes]

    cfg: dict = {
        "mixed-port": int(st["mixed_port"]),
        "allow-lan": bool(st["allow_lan"]),
        "bind-address": st["bind_address"],
        "ipv6": bool(st["ipv6"]),
        "mode": str(st["mode"]).lower(),
        "log-level": str(st["log_level"]).lower(),
        "unified-delay": bool(st["unified_delay"]),
        "tcp-concurrent": bool(st["tcp_concurrent"]),
        "find-process-mode": "off",
        "geo-auto-update": False,
        "external-controller": st["controller"],
        "secret": st["secret"],
        "profile": {"store-selected": True, "store-fake-ip": True},
    }
    if int(st["redir_port"] or 0):
        cfg["redir-port"] = int(st["redir_port"])
    if int(st["tproxy_port"] or 0):
        cfg["tproxy-port"] = int(st["tproxy_port"])

    if st["tun"]:
        cfg["tun"] = {
            "enable": True,
            "stack": str(st["tun_stack"] or "system"),
            "device": "mitui0",
            "auto-route": True,
            "auto-redirect": False,
            "auto-detect-interface": True,
            "dns-hijack": ["any:53", "tcp://any:53"],
            "strict-route": False,
        }

    if st["dns_enable"]:
        cfg["dns"] = _dns(st)

    cfg["proxies"] = nodes
    cfg["proxy-groups"] = _groups(st, names)
    cfg["rules"] = _rules(st)
    return cfg


def _apply_defaults(st: Settings, nodes: list) -> list:
    out = []
    for node in nodes:
        node = dict(node)
        if st["udp"] and "udp" not in node and node.get("type") != "hysteria2":
            node["udp"] = True
        if st["skip_cert_verify"] and "skip-cert-verify" not in node:
            node["skip-cert-verify"] = True
        out.append(node)
    return out


def _dns(st: Settings) -> dict:
    dns: dict = {
        "enable": True,
        "listen": "127.0.0.1:1053",
        "ipv6": bool(st["ipv6"]),
        "prefer-h3": False,
        "respect-rules": False,
        "default-nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"],
        "nameserver": [
            "https://dns.alidns.com/dns-query",
            "https://doh.pub/dns-query",
        ],
        # 在本地解析代理服务器的主机名，绝不通过代理解析。
        "proxy-server-nameserver": ["https://dns.alidns.com/dns-query"],
    }
    if st["fake_ip"]:
        dns["enhanced-mode"] = "fake-ip"
        dns["fake-ip-range"] = "198.18.0.1/16"
        dns["fake-ip-filter"] = [
            "*.lan", "*.local", "*.localhost", "localhost.ptlogin2.qq.com",
            "+.srv.nintendo.net", "+.stun.playstation.net",
            "+.msftconnecttest.com", "+.msftncsi.com",
            "time.*.com", "ntp.*.com", "+.pool.ntp.org",
        ]
    else:
        dns["enhanced-mode"] = "normal"
    if not st["tun"]:
        # 未启用 TUN 时，没有流量会经由 53 端口进入核心程序，因此解析器
        # only used for rule matching -- don't open a listener nobody uses.
        dns.pop("listen", None)
    return dns


def _groups(st: Settings, names: list) -> list:
    members = list(names)
    groups = [
        {
            "name": PROXY_GROUP,
            "type": "select",
            "proxies": ([AUTO_GROUP] if members else []) + members + ["DIRECT"],
        }
    ]
    if members:
        groups.append({
            "name": AUTO_GROUP,
            "type": "url-test",
            "url": st["test_url"],
            "interval": int(st["auto_group_interval"]),
            "tolerance": 50,
            "lazy": True,
            "proxies": members,
        })
    else:
        groups[0]["proxies"] = ["DIRECT"]
    return groups


def geo_db_present(home=None) -> bool:
    """当 mihomo 无需下载即可解析 GeoIP 规则时返回 True。"""
    base = home or paths.CORE_HOME
    return any((base / name).exists() for name in MMDB_NAMES)


def _rules(st: Settings) -> list:
    rules = list(LOCAL_RULES)
    if st["cn_direct"] and geo_db_present():
        rules += [
            "GEOIP,private,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
        ]
    rules.append("MATCH,%s" % PROXY_GROUP)
    return rules


def write(st: Settings, nodes: list, path=None) -> str:
    """生成配置并以原子方式写入，返回写入文件的路径。"""
    import os
    import tempfile

    paths.ensure_dirs()
    target = path or paths.CORE_CONFIG
    text = "# 由 mitui 生成，重新生成时此处的修改将被覆盖。\n"
    text += yamlio.dump(build(st, nodes))
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".config-")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, target)
    os.chmod(target, 0o600)
    return str(target)
