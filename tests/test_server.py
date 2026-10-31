"""HTTP server tests: binding, request hygiene and the JSON API end to end."""

import http.client
import json
import tempfile
import threading
import unittest
import unittest.mock

from vigil import server
from .helpers import make_proc


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        proc_root = make_proc(cls.tmp.name)
        cls.app = server.App(f"{cls.tmp.name}/data", interval=60, proc_root=proc_root,
                             start_monitor=False)
        cls.app.monitor.poll_once()  # one synthetic poll; runs as the test user
        cls.httpd = server.make_server(cls.app, port=0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.app.store.close()
        cls.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = {"Host": f"127.0.0.1:{self.port}"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res, data

    def get_json(self, path):
        res, data = self.request("GET", path)
        self.assertEqual(res.status, 200, data)
        return json.loads(data)

    def test_binds_loopback_only(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")
        self.assertEqual(server.HOST, "127.0.0.1")

    def test_rejects_foreign_host_header(self):
        # A web page using DNS rebinding would arrive with its own hostname.
        res, _ = self.request("GET", "/api/status", headers={"Host": f"evil.example:{self.port}"})
        self.assertEqual(res.status, 403)
        res, _ = self.request("GET", "/api/status", headers={"Host": f"localhost:{self.port}"})
        self.assertEqual(res.status, 200)

    def test_static_and_traversal(self):
        res, data = self.request("GET", "/")
        self.assertEqual(res.status, 200)
        self.assertIn(b"<title>Vigil</title>", data)
        self.assertIn("script-src 'self'", res.getheader("Content-Security-Policy"))
        self.assertEqual(res.getheader("X-Content-Type-Options"), "nosniff")
        res, _ = self.request("GET", "/static/app.js")
        self.assertEqual(res.getheader("Content-Type"), "text/javascript; charset=utf-8")
        for bad in ("/static/../vigil/server.py", "/static/%2e%2e/README.md", "/static/x/../app.js",
                    "/vigil/server.py", "/static/.hidden.js"):
            with self.subTest(path=bad):
                res, _ = self.request("GET", bad)
                self.assertEqual(res.status, 404)

    def test_bundled_fonts(self):
        res, data = self.request("GET", "/static/fonts/Inter-Variable.woff2")
        self.assertEqual(res.status, 200)
        self.assertEqual(res.getheader("Content-Type"), "font/woff2")
        self.assertIn("immutable", res.getheader("Cache-Control"))
        self.assertTrue(data.startswith(b"wOF2"))
        res, data = self.request("GET", "/static/fonts/OFL-Inter.txt")
        self.assertIn(b"SIL OPEN FONT LICENSE", data)
        for bad in ("/static/fonts/../app.js", "/static/fonts/x/y.woff2", "/static/fonts/a.ttf"):
            with self.subTest(path=bad):
                res, _ = self.request("GET", bad)
                self.assertEqual(res.status, 404)

    def test_status(self):
        s = self.get_json("/api/status")
        self.assertEqual(s["polls"], 1)
        self.assertIsNone(s["last_error"])
        self.assertEqual(s["sockets"], 17)
        self.assertEqual(s["missing_tables"], [])
        self.assertIsNotNone(s["baseline_at"])
        for h in s["hidden"]:
            self.assertTrue(h["explanation"])

    def test_graph_and_details(self):
        g = self.get_json("/api/graph?window=900&scopes=internet,lan,reserved")
        names = {p["name"] for p in g["programs"]}
        self.assertIn("firefox", names)
        self.assertIn("agent", names)
        lan = self.get_json("/api/graph?window=900&scopes=lan")
        self.assertEqual({e["ip"] for e in lan["edges"]}, {"10.0.0.5", "192.168.1.1"})
        bogus = self.get_json("/api/graph?scopes=nonsense")
        self.assertEqual(bogus["edges"], [])

        ff = self.get_json("/api/program?key=%2Fusr%2Flib%2Ffirefox%2Ffirefox")
        self.assertEqual(ff["name"], "firefox")
        self.assertTrue(ff["timeline"])
        dest = self.get_json("/api/destination?ip=198.51.100.30")
        self.assertIn("firefox", {p["name"] for p in dest["pairs"]})
        res, _ = self.request("GET", "/api/program?key=missing")
        self.assertEqual(res.status, 404)
        listeners = self.get_json("/api/listeners")["listeners"]
        self.assertIn(22, {l["local_port"] for l in listeners})

    def test_keep_alive(self):
        # One TCP connection for many polls, so the UI does not pollute the map.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        for _ in range(3):
            conn.request("GET", "/api/status", headers={"Host": f"127.0.0.1:{self.port}"})
            res = conn.getresponse()
            res.read()
            self.assertEqual(res.status, 200)
            self.assertFalse(res.will_close)
        conn.close()

    def write(self, method, path, payload, **extra):
        headers = {"X-Vigil": "1", "Content-Type": "application/json",
                   "Origin": f"http://127.0.0.1:{self.port}"}
        headers.update(extra)
        headers = {k: v for k, v in headers.items() if v is not None}
        return self.request(method, path, body=json.dumps(payload).encode(), headers=headers)

    def test_writes_need_the_vigil_page(self):
        rule = {"program": "/usr/bin/x", "port": 4444, "reason": "test"}
        res, _ = self.write("POST", "/api/allowlist", rule, **{"X-Vigil": None})
        self.assertEqual(res.status, 403)  # a plain cross-site form post has no custom header
        res, _ = self.write("POST", "/api/allowlist", rule, Origin="http://evil.example")
        self.assertEqual(res.status, 403)
        res, _ = self.write("POST", "/api/allowlist", {"program": "x"})
        self.assertEqual(res.status, 400)  # no reason given

    def test_allowlist_round_trip(self):
        res, data = self.write("POST", "/api/allowlist",
                               {"program": "/usr/bin/x", "port": 4444, "reason": "test rule"})
        self.assertEqual(res.status, 200, data)
        rid = json.loads(data)["rule"]["id"]
        rules = self.get_json("/api/allowlist")["rules"]
        self.assertIn(rid, {r["id"] for r in rules})
        self.assertIn("builtin-ntp", {r["id"] for r in rules})
        res, _ = self.write("DELETE", f"/api/allowlist?id={rid}", {})
        self.assertEqual(res.status, 200)
        res, _ = self.write("DELETE", f"/api/allowlist?id={rid}", {})
        self.assertEqual(res.status, 404)

    def test_alert_dismissal(self):
        st = self.app.store
        with st.lock, st.db:
            cur = st.db.execute(
                "INSERT INTO alerts(fingerprint,program,ip,port,proto,direction,score,peak_score,"
                "findings,status,first_raised,last_updated) VALUES('t|1.2.3.4|out',"
                "'/usr/lib/firefox/firefox','1.2.3.4',1,'tcp','out',80,80,'[]','open',1,1)")
            aid = cur.lastrowid
        self.assertIn(aid, {a["id"] for a in self.get_json("/api/alerts")["alerts"]})
        res, _ = self.write("POST", "/api/alerts/update", {"id": aid, "status": "nope"})
        self.assertEqual(res.status, 400)
        res, _ = self.write("POST", "/api/alerts/update", {"id": 999999, "status": "dismissed"})
        self.assertEqual(res.status, 404)
        res, _ = self.write("POST", "/api/alerts/update",
                            {"id": aid, "status": "dismissed", "note": "my backup job"})
        self.assertEqual(res.status, 200)
        self.assertNotIn(aid, {a["id"] for a in self.get_json("/api/alerts")["alerts"]})
        dismissed = self.get_json("/api/alerts?status=dismissed")["alerts"]
        self.assertEqual(dismissed[0]["note"], "my backup job")
        ev = st.one("SELECT * FROM events WHERE kind='alert_status'")
        self.assertEqual(ev["source"], "analyst (Vigil UI)")

    def test_status_reports_scoring(self):
        s = self.get_json("/api/status")
        self.assertEqual(s["alert_threshold"], 70)
        self.assertIsNotNone(s["last_scored_at"])

    def test_intel_endpoints(self):
        st = self.get_json("/api/intel")
        self.assertEqual([f["name"] for f in st["feeds"]], ["feodo", "sslbl", "urlhaus"])
        self.assertIsNone(st["feeds"][0]["status"])  # never downloaded: nothing is automatic
        res, _ = self.request("GET", "/api/lookup?ip=nope")
        self.assertEqual(res.status, 400)
        found = self.get_json("/api/lookup?ip=198.51.100.30")
        self.assertEqual(found["scope"], "reserved")
        self.assertEqual(found["intel"], [])
        self.assertIsNotNone(found["seen"])  # the fixture's firefox talked to it
        self.assertIsNone(self.get_json("/api/lookup?ip=192.0.2.200")["seen"])

    def test_downloads_cannot_be_triggered_cross_site(self):
        with unittest.mock.patch.object(self.app.enricher, "update_feeds") as upd:
            res, _ = self.write("POST", "/api/intel/update", {"what": "feeds"}, **{"X-Vigil": None})
            self.assertEqual(res.status, 403)
            res, _ = self.write("POST", "/api/intel/update", {"what": "everything"})
            self.assertEqual(res.status, 400)
            upd.assert_not_called()

    def test_file_inspection_round_trip(self):
        from . import synth
        data = synth.docm_dropper()
        headers = {"X-Vigil": "1", "Content-Type": "application/octet-stream",
                   "X-Filename": "Q3%20invoice.docm"}
        res, _ = self.request("POST", "/api/inspect", body=data,
                              headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(res.status, 403)  # no other web page can submit files
        res, body = self.request("POST", "/api/inspect", body=data, headers=headers)
        self.assertEqual(res.status, 200, body)
        report = json.loads(body)
        self.assertEqual((report["name"], report["verdict"]), ("Q3 invoice.docm", "Likely malicious"))
        listed = self.get_json("/api/inspections")["inspections"]
        self.assertIn(report["id"], [i["id"] for i in listed])
        again = self.get_json(f"/api/inspection?id={report['id']}")
        self.assertEqual(again["hashes"], report["hashes"])
        self.assertEqual(again["source"], "upload via the Vigil page")
        res, _ = self.write("DELETE", f"/api/inspection?id={report['id']}", {})
        self.assertEqual(res.status, 200)
        res, _ = self.request("GET", f"/api/inspection?id={report['id']}")
        self.assertEqual(res.status, 404)

    def test_oversized_upload_refused_before_reading(self):
        res, body = self.request("POST", "/api/inspect", body=b"x",
                                 headers={"X-Vigil": "1", "Content-Length": str(500 * 2**20)})
        self.assertEqual(res.status, 400)
        self.assertIn(b"larger than", body)

    def test_unknown_routes(self):
        res, _ = self.request("POST", "/api/nothing", body=b"{}",
                              headers={"X-Vigil": "1", "Content-Type": "application/json"})
        self.assertEqual(res.status, 404)


if __name__ == "__main__":
    unittest.main()
