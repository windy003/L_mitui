"""Exercise the controller client against a stub of the mihomo API."""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mitui.api import Api, ApiError  # noqa: E402

SECRET = "t0ken"
seen = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _auth_ok(self):
        return self.headers.get("Authorization") == "Bearer %s" % SECRET

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        seen.append(("GET", self.path))
        if not self._auth_ok():
            return self._send({"message": "unauthorized"}, 401)
        if self.path == "/version":
            return self._send({"version": "1.19.2", "meta": True})
        if self.path == "/proxies":
            return self._send({"proxies": {
                "PROXY": {"type": "Selector", "now": "HK 01",
                          "all": ["AUTO", "HK 01"]},
                "HK 01": {"type": "Trojan",
                          "history": [{"delay": 85}]},
                "Dead": {"type": "Trojan", "history": [{"delay": 0}]},
            }})
        if self.path.startswith("/proxies/HK%2001/delay"):
            return self._send({"delay": 77})
        if self.path.startswith("/proxies/Dead/delay"):
            return self._send({"message": "timeout"}, 504)
        if self.path.startswith("/group/AUTO/delay"):
            return self._send({"HK 01": 90, "Dead": 0})
        if self.path == "/connections":
            return self._send({"connections": [{"id": "a"}, {"id": "b"}],
                               "uploadTotal": 1024, "downloadTotal": 4096})
        if self.path == "/traffic":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(3):
                chunk = json.dumps({"up": i * 10, "down": i * 100}).encode() + b"\n"
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.write(b"0\r\n\r\n")
            return
        self._send({"message": "not found"}, 404)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        seen.append(("PUT", self.path, body))
        self._send({})

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        seen.append(("PATCH", self.path, body))
        self._send({})


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        del seen[:]
        self.api = Api("127.0.0.1:%d" % self.port, SECRET)

    def test_controller_forms(self):
        for form in ("127.0.0.1:%d" % self.port, "http://127.0.0.1:%d" % self.port,
                     ":%d" % self.port):
            self.assertTrue(Api(form, SECRET).alive(), form)

    def test_version_and_alive(self):
        self.assertEqual(self.api.version()["version"], "1.19.2")
        self.assertTrue(self.api.alive())

    def test_bad_secret_is_not_alive(self):
        self.assertFalse(Api("127.0.0.1:%d" % self.port, "wrong").alive())

    def test_proxies(self):
        data = self.api.proxies()
        self.assertEqual(data["PROXY"]["now"], "HK 01")

    def test_select_quotes_group_and_sends_name(self):
        self.api.select("PROXY", "HK 01")
        self.assertIn(("PUT", "/proxies/PROXY", {"name": "HK 01"}), seen)

    def test_delay_quotes_the_node_name(self):
        self.assertEqual(self.api.delay("HK 01", "http://x/204", 2000), 77)

    def test_delay_timeout_raises(self):
        with self.assertRaises(ApiError):
            self.api.delay("Dead", "http://x/204", 1000)

    def test_group_delay(self):
        got = self.api.group_delay("AUTO", "http://x/204", 2000)
        self.assertEqual(got, {"HK 01": 90, "Dead": 0})

    def test_set_mode(self):
        self.api.set_mode("global")
        self.assertIn(("PATCH", "/configs", {"mode": "global"}), seen)

    def test_reload_sends_path(self):
        self.api.reload("/tmp/config.yaml")
        self.assertIn(("PUT", "/configs?force=true",
                       {"path": "/tmp/config.yaml"}), seen)

    def test_connections(self):
        data = self.api.connections()
        self.assertEqual(len(data["connections"]), 2)

    def test_traffic_stream(self):
        got = list(self.api.traffic())
        self.assertEqual(got, [{"up": 0, "down": 0}, {"up": 10, "down": 100},
                               {"up": 20, "down": 200}])

    def test_unreachable_core(self):
        with self.assertRaises(ApiError):
            Api("127.0.0.1:1", SECRET).proxies()


class TestAppWithStubCore(unittest.TestCase):
    """App-level latency logic driven by the stub controller."""

    @classmethod
    def setUpClass(cls):
        TestApi.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TestApi.tearDownClass.__func__(cls)

    def setUp(self):
        # keep the real HOME clean: App() creates its config/data directories
        import importlib
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = {k: os.environ.get(k) for k in
                      ("HOME", "USERPROFILE", "XDG_CONFIG_HOME",
                       "XDG_DATA_HOME", "XDG_RUNTIME_DIR")}
        os.environ["HOME"] = os.environ["USERPROFILE"] = self.tmp.name
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmp.name, "c")
        os.environ["XDG_DATA_HOME"] = os.path.join(self.tmp.name, "d")
        os.environ["XDG_RUNTIME_DIR"] = os.path.join(self.tmp.name, "r")
        from mitui import paths
        importlib.reload(paths)
        for mod in ("mitui.settings", "mitui.confgen", "mitui.core", "mitui.app"):
            if mod in sys.modules:
                importlib.reload(sys.modules[mod])

    def tearDown(self):
        for key, val in self.saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        self.tmp.cleanup()

    def test_refresh_and_test_all(self):
        from mitui.app import TIMEOUT, App
        from mitui.settings import Settings

        st = Settings({"controller": "127.0.0.1:%d" % self.port,
                       "secret": SECRET})
        app = App(st)
        app.nodes = [{"name": "HK 01", "type": "trojan"},
                     {"name": "Dead", "type": "trojan"}]

        app.refresh_proxies()
        self.assertEqual(app.now, "HK 01")
        self.assertEqual(app.delays["HK 01"], 85)
        self.assertEqual(app.delays["Dead"], TIMEOUT)

        tested, failed = app.test_all()
        self.assertEqual((tested, failed), (2, 1))
        self.assertEqual(app.delays["HK 01"], 90)
        self.assertEqual(app.delays["Dead"], TIMEOUT)

        app.refresh_conns()
        self.assertEqual(app.conns, 2)
        self.assertEqual(app.down_total, 4096)


if __name__ == "__main__":
    unittest.main()
