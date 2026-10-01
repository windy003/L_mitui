"""Parser / config generation tests. Run: python -m unittest discover tests"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mitui import subs, yamlio  # noqa: E402
from mitui.confgen import build  # noqa: E402
from mitui.settings import Settings  # noqa: E402


def b64(text):
    return base64.b64encode(text.encode()).decode()


class TestTrojan(unittest.TestCase):
    def test_plain(self):
        node = subs.parse_uri("trojan://pass123@a.example.com:443#HK%20Node%201")
        self.assertEqual(node["type"], "trojan")
        self.assertEqual(node["server"], "a.example.com")
        self.assertEqual(node["port"], 443)
        self.assertEqual(node["password"], "pass123")
        self.assertEqual(node["name"], "HK Node 1")
        self.assertTrue(node["udp"])

    def test_url_encoded_password(self):
        node = subs.parse_uri("trojan://p%40ss%3Aword@h.example:8443#x")
        self.assertEqual(node["password"], "p@ss:word")
        self.assertEqual(node["port"], 8443)

    def test_sni_and_insecure(self):
        node = subs.parse_uri(
            "trojan://pw@1.2.3.4:443?sni=cdn.example.com&allowInsecure=1"
            "&alpn=h2%2Chttp%2F1.1&fp=chrome#JP")
        self.assertEqual(node["sni"], "cdn.example.com")
        self.assertTrue(node["skip-cert-verify"])
        self.assertEqual(node["alpn"], ["h2", "http/1.1"])
        self.assertEqual(node["client-fingerprint"], "chrome")

    def test_websocket(self):
        node = subs.parse_uri(
            "trojan://pw@g.example:443?type=ws&path=%2Fray&host=ws.example"
            "&sni=ws.example#WS")
        self.assertEqual(node["network"], "ws")
        self.assertEqual(node["ws-opts"]["path"], "/ray")
        self.assertEqual(node["ws-opts"]["headers"]["Host"], "ws.example")

    def test_grpc(self):
        node = subs.parse_uri(
            "trojan://pw@g.example:443?type=grpc&serviceName=GunService#G")
        self.assertEqual(node["network"], "grpc")
        self.assertEqual(node["grpc-opts"]["grpc-service-name"], "GunService")

    def test_no_fragment_gets_a_name(self):
        node = subs.parse_uri("trojan://pw@h.example:443")
        self.assertEqual(node["name"], "h.example:443")

    def test_garbage(self):
        self.assertIsNone(subs.parse_uri("trojan://"))
        self.assertIsNone(subs.parse_uri("not a uri"))
        self.assertIsNone(subs.parse_uri("ftp://x@y:1"))


class TestOtherProtocols(unittest.TestCase):
    def test_ss_legacy(self):
        uri = "ss://" + b64("aes-256-gcm:secretpw@ss.example:8388") + "#SS1"
        node = subs.parse_uri(uri)
        self.assertEqual(node["type"], "ss")
        self.assertEqual(node["cipher"], "aes-256-gcm")
        self.assertEqual(node["password"], "secretpw")
        self.assertEqual(node["port"], 8388)

    def test_ss_sip002_with_obfs(self):
        uri = ("ss://" + b64("chacha20-ietf-poly1305:pw")
               + "@ss.example:443?plugin=obfs-local%3Bobfs%3Dtls"
                 "%3Bobfs-host%3Dbing.com#SS2")
        node = subs.parse_uri(uri)
        self.assertEqual(node["plugin"], "obfs")
        self.assertEqual(node["plugin-opts"]["mode"], "tls")
        self.assertEqual(node["plugin-opts"]["host"], "bing.com")

    def test_vmess(self):
        payload = ('{"v":"2","ps":"VM","add":"v.example","port":"443",'
                   '"id":"11111111-2222-3333-4444-555555555555","aid":"0",'
                   '"net":"ws","path":"/p","host":"h.example","tls":"tls"}')
        node = subs.parse_uri("vmess://" + b64(payload))
        self.assertEqual(node["type"], "vmess")
        self.assertEqual(node["name"], "VM")
        self.assertEqual(node["port"], 443)
        self.assertTrue(node["tls"])
        self.assertEqual(node["network"], "ws")
        self.assertEqual(node["ws-opts"]["path"], "/p")

    def test_vless_reality(self):
        node = subs.parse_uri(
            "vless://aaaa-bbbb@r.example:443?security=reality&pbk=KEY&sid=ab"
            "&sni=www.apple.com&fp=chrome&type=tcp&flow=xtls-rprx-vision#R")
        self.assertEqual(node["type"], "vless")
        self.assertTrue(node["tls"])
        self.assertEqual(node["reality-opts"]["public-key"], "KEY")
        self.assertEqual(node["flow"], "xtls-rprx-vision")

    def test_hysteria2(self):
        node = subs.parse_uri(
            "hysteria2://pw@h2.example:8443?sni=h2.example&insecure=1"
            "&obfs=salamander&obfs-password=xyz#H2")
        self.assertEqual(node["type"], "hysteria2")
        self.assertTrue(node["skip-cert-verify"])
        self.assertEqual(node["obfs-password"], "xyz")


class TestSubscriptionPayloads(unittest.TestCase):
    def test_base64_bundle(self):
        raw = "\n".join([
            "trojan://pw1@a.example:443#A",
            "trojan://pw2@b.example:443#B",
            "ss://" + b64("aes-128-gcm:pw@c.example:8388") + "#C",
        ])
        nodes = subs.parse(b64(raw))
        self.assertEqual([n["name"] for n in nodes], ["A", "B", "C"])

    def test_plain_lines_with_noise(self):
        raw = ("# comment\n\ntrojan://pw@a.example:443#A\n"
               "garbage line\ntrojan://pw@b.example:443#B\n")
        nodes = subs.parse(raw)
        self.assertEqual(len(nodes), 2)

    def test_clash_yaml(self):
        raw = """
port: 7890
proxies:
  - name: "Trojan HK"
    type: trojan
    server: hk.example.com
    port: 443
    password: pw
    sni: hk.example.com
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /tr
      headers:
        Host: hk.example.com
  - {name: Flow JP, type: trojan, server: jp.example.com, port: 443, password: pw2, udp: true}
  - name: Unsupported
    type: weird-protocol
    server: x
    port: 1
proxy-groups:
  - name: g
    type: select
    proxies: [Trojan HK]
"""
        nodes = subs.parse(raw)
        self.assertEqual([n["name"] for n in nodes], ["Trojan HK", "Flow JP"])
        self.assertEqual(nodes[0]["ws-opts"]["headers"]["Host"], "hk.example.com")
        self.assertEqual(nodes[1]["server"], "jp.example.com")
        self.assertEqual(nodes[1]["port"], 443)

    def test_duplicate_names(self):
        raw = "\n".join(["trojan://pw@a.example:443#Same"] * 3)
        nodes = subs.parse(raw)
        self.assertEqual([n["name"] for n in nodes],
                         ["Same", "Same #2", "Same #3"])

    def test_empty(self):
        self.assertEqual(subs.parse(""), [])
        self.assertEqual(subs.parse("totally unrelated text"), [])

    def test_b64_without_padding(self):
        raw = "trojan://pw@a.example:443#A"
        self.assertIn("trojan", subs.b64decode(b64(raw).rstrip("=")))


class TestYamlIO(unittest.TestCase):
    def test_roundtrip(self):
        obj = {
            "mixed-port": 7890,
            "allow-lan": False,
            "proxies": [
                {"name": "节点 1", "type": "trojan", "server": "a.b",
                 "port": 443, "password": "p:w#d",
                 "alpn": ["h2", "http/1.1"],
                 "ws-opts": {"path": "/x", "headers": {"Host": "a.b"}}},
            ],
            "rules": ["MATCH,PROXY"],
            "empty": {},
        }
        text = yamlio.dump(obj)
        back = yamlio._Parser(text).parse()   # exercise the built-in parser
        self.assertEqual(back["mixed-port"], 7890)
        self.assertIs(back["allow-lan"], False)
        self.assertEqual(back["proxies"][0]["name"], "节点 1")
        self.assertEqual(back["proxies"][0]["password"], "p:w#d")
        self.assertEqual(back["proxies"][0]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(back["proxies"][0]["ws-opts"]["headers"]["Host"], "a.b")
        self.assertEqual(back["rules"], ["MATCH,PROXY"])

    def test_quoting_dangerous_scalars(self):
        for value in ("yes", "no", "true", "123", "1.5", "", "a: b", "#x",
                      "*anchor", "{brace}"):
            text = yamlio.dump({"k": value})
            back = yamlio._Parser(text).parse()
            self.assertEqual(back["k"], value, "failed for %r" % value)

    def test_flow_parsing(self):
        got = yamlio.parse_flow('{a: 1, b: "x, y", c: [1, 2], d: {e: f}}')
        self.assertEqual(got, {"a": 1, "b": "x, y", "c": [1, 2],
                               "d": {"e": "f"}})


class TestConfGen(unittest.TestCase):
    def setUp(self):
        self.st = Settings({"secret": "s3cret", "mixed_port": 7891})
        self.nodes = subs.parse("\n".join([
            "trojan://pw@a.example:443#A",
            "trojan://pw@b.example:443#B",
        ]))

    def test_structure(self):
        cfg = build(self.st, self.nodes)
        self.assertEqual(cfg["mixed-port"], 7891)
        self.assertEqual(cfg["secret"], "s3cret")
        self.assertEqual(len(cfg["proxies"]), 2)
        groups = {g["name"]: g for g in cfg["proxy-groups"]}
        self.assertIn("PROXY", groups)
        self.assertIn("AUTO", groups)
        self.assertEqual(groups["AUTO"]["proxies"], ["A", "B"])
        self.assertEqual(groups["PROXY"]["proxies"], ["AUTO", "A", "B", "DIRECT"])
        self.assertEqual(cfg["rules"][-1], "MATCH,PROXY")
        # must serialize and parse back cleanly
        back = yamlio._Parser(yamlio.dump(cfg)).parse()
        self.assertEqual(back["proxies"][0]["name"], "A")

    def test_no_nodes_still_valid(self):
        cfg = build(self.st, [])
        self.assertEqual(cfg["proxies"], [])
        self.assertEqual(len(cfg["proxy-groups"]), 1)
        self.assertEqual(cfg["proxy-groups"][0]["proxies"], ["DIRECT"])

    def test_tun_and_direct_mode(self):
        self.st["tun"] = True
        self.st["cn_direct"] = False
        cfg = build(self.st, self.nodes)
        self.assertTrue(cfg["tun"]["enable"])
        self.assertNotIn("GEOIP,CN,DIRECT", cfg["rules"])

    def test_geo_rules_only_when_the_database_is_on_disk(self):
        """A GEOIP rule with no mmdb makes mihomo block on a download."""
        import tempfile
        from pathlib import Path

        import mitui.confgen as cg

        self.st["cn_direct"] = True
        saved = cg.paths.CORE_HOME
        try:
            with tempfile.TemporaryDirectory() as tmp:
                cg.paths.CORE_HOME = Path(tmp)
                # no database yet -> no geo rules at all
                rules = build(self.st, self.nodes)["rules"]
                self.assertNotIn("GEOIP,CN,DIRECT", rules)
                self.assertEqual(rules[-1], "MATCH,PROXY")

                (Path(tmp) / "geoip.metadb").write_bytes(b"x")
                rules = build(self.st, self.nodes)["rules"]
                self.assertIn("GEOIP,CN,DIRECT", rules)
                self.assertIn("GEOIP,private,DIRECT,no-resolve", rules)
        finally:
            cg.paths.CORE_HOME = saved

    def test_removed_global_client_fingerprint_key(self):
        """mihomo >= 1.19.30 errors on global-client-fingerprint."""
        cfg = build(self.st, self.nodes)
        self.assertNotIn("global-client-fingerprint", cfg)

    def test_skip_cert_verify_default(self):
        self.st["skip_cert_verify"] = True
        cfg = build(self.st, self.nodes)
        self.assertTrue(all(p["skip-cert-verify"] for p in cfg["proxies"]))


if __name__ == "__main__":
    unittest.main()
