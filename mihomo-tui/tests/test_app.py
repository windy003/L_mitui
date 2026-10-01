"""End to end test over a throwaway HOME: link -> settings -> config.yaml."""

import importlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAppFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.saved = {k: os.environ.get(k) for k in
                      ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                       "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "USERPROFILE")}
        os.environ["HOME"] = root
        os.environ["USERPROFILE"] = root
        os.environ["XDG_CONFIG_HOME"] = os.path.join(root, "config")
        os.environ["XDG_DATA_HOME"] = os.path.join(root, "data")
        os.environ["XDG_CACHE_HOME"] = os.path.join(root, "cache")
        os.environ["XDG_RUNTIME_DIR"] = os.path.join(root, "run")

        from mitui import paths
        importlib.reload(paths)
        self.paths = paths
        for mod in ("mitui.settings", "mitui.confgen", "mitui.core",
                    "mitui.app"):
            if mod in sys.modules:
                importlib.reload(sys.modules[mod])

    def tearDown(self):
        for key, val in self.saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        self.tmp.cleanup()

    def test_link_to_config(self):
        from mitui import yamlio
        from mitui.app import App

        app = App()
        self.assertEqual(app.nodes, [])

        node = app.add_link(
            "trojan://s3cret@hk.example.com:443?sni=hk.example.com"
            "&allowInsecure=1&type=ws&path=%2Ftr#HK%20%E9%A6%99%E6%B8%AF")
        self.assertEqual(node["type"], "trojan")
        self.assertEqual(node["name"], "HK 香港")
        self.assertEqual(len(app.nodes), 1)

        path = app.write_config()
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        cfg = yamlio.load(text)

        self.assertEqual(cfg["proxies"][0]["name"], "HK 香港")
        self.assertEqual(cfg["proxies"][0]["password"], "s3cret")
        self.assertEqual(cfg["proxies"][0]["ws-opts"]["path"], "/tr")
        self.assertIs(cfg["proxies"][0]["skip-cert-verify"], True)
        self.assertEqual(cfg["external-controller"], "127.0.0.1:9090")
        self.assertEqual(cfg["secret"], app.st["secret"])
        self.assertEqual(cfg["proxy-groups"][0]["proxies"],
                         ["AUTO", "HK 香港", "DIRECT"])
        self.assertEqual(cfg["rules"][-1], "MATCH,PROXY")

        # settings survive a reload, and the secret is not world readable
        from mitui.settings import Settings
        again = Settings.load()
        self.assertEqual(again["extra_nodes"][0]["name"], "HK 香港")
        if os.name == "posix":
            mode = os.stat(self.paths.SETTINGS_FILE).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_subscription_payload_to_config(self):
        import base64

        from mitui import yamlio
        from mitui.app import App

        raw = base64.b64encode("\n".join([
            "trojan://pw1@a.example:443#A",
            "trojan://pw2@b.example:443?type=grpc&serviceName=gs#B",
        ]).encode()).decode()

        app = App()
        sub = app.st.add_sub("https://example.com/sub")
        # bypass the network: feed a payload straight through the parser
        from mitui import subs as subs_mod
        nodes = subs_mod.parse(raw)
        sub["nodes"] = nodes
        sub["count"] = len(nodes)
        app.st.save()
        app.reload_nodes()

        self.assertEqual(len(app.nodes), 2)
        with open(app.write_config(), encoding="utf-8") as fh:
            cfg = yamlio.load(fh.read())
        self.assertEqual([p["name"] for p in cfg["proxies"]], ["A", "B"])
        self.assertEqual(cfg["proxies"][1]["grpc-opts"]["grpc-service-name"],
                         "gs")
        auto = [g for g in cfg["proxy-groups"] if g["name"] == "AUTO"][0]
        self.assertEqual(auto["proxies"], ["A", "B"])


if __name__ == "__main__":
    unittest.main()
