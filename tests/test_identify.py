"""Identify: browser tabs, host names, TLS badges. All data here is SYNTHETIC: a fake
browser profile and session file built at test time, a fake Chromium history, and a
self-signed test certificate (tests/fixtures/tls) served on 127.0.0.1 only."""

import json
import os
import re
import socket
import sqlite3
import ssl
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from vigil import identify

TLS = Path(__file__).parent / "fixtures" / "tls"


def lz4_literals(data):
    """Encode bytes as one LZ4 block of literals only (valid LZ4, no compression)."""
    n = len(data)
    out = bytearray()
    if n < 15:
        out.append(n << 4)
    else:
        out.append(0xF0)
        rest = n - 15
        while rest >= 255:
            out.append(255)
            rest -= 255
        out.append(rest)
    return bytes(out) + data


def mozlz4(obj):
    raw = json.dumps(obj).encode()
    return b"mozLz40\0" + struct.pack("<I", len(raw)) + lz4_literals(raw)


class Lz4Tests(unittest.TestCase):
    def test_literals_and_overlapping_match(self):
        # "abcd" then a match of 8 at offset 4 -> "abcdabcdabcd"
        block = bytes([0x44]) + b"abcd" + bytes([4, 0])
        self.assertEqual(identify.lz4_block(block, 12), b"abcdabcdabcd")
        long = b"x" * 300
        self.assertEqual(identify.lz4_block(lz4_literals(long), 300), long)
        with self.assertRaises(ValueError):
            identify.lz4_block(bytes([0x04]) + bytes([9, 0]), 10)  # offset beyond output


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name
        prof = Path(self.home, ".librewolf", "syn123.default-default")
        (prof / "sessionstore-backups").mkdir(parents=True)
        (prof / "prefs.js").write_text("// synthetic\n")
        session = {"windows": [{"tabs": [
            {"index": 2, "lastAccessed": 1761900000000, "entries": [
                {"url": "https://example.org/old", "title": "old page"},
                {"url": "https://www.virustotal.com/gui/file/abc?secret=1", "title": "VirusTotal - File - abc"}]},
            {"index": 1, "entries": [{"url": "about:preferences", "title": "Settings"}]},
        ]}]}
        (prof / "sessionstore-backups" / "recovery.jsonlz4").write_bytes(mozlz4(session))
        (prof / "SiteSecurityServiceState.txt").write_text(
            "www.virustotal.com:HSTS\t0\t19000\t1790000000000,1,1\n"
            "example.net^partitionKey=%28https%2Cx.test%29:HSTS\t0\t1\t1,1,0\n")
        hist_dir = Path(self.home, ".config", "chromium", "Default")
        hist_dir.mkdir(parents=True)
        db = sqlite3.connect(hist_dir / "History")
        db.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER)")
        now = time.time()
        db.execute("INSERT INTO urls(url, title, last_visit_time) VALUES(?,?,?)",
                   ("https://docs.python.org/3/", "Python docs", int((now - 60 + 11644473600) * 1e6)))
        db.execute("INSERT INTO urls(url, title, last_visit_time) VALUES(?,?,?)",
                   ("https://old.example/", "too old", int((now - 99999 + 11644473600) * 1e6)))
        db.commit()
        db.close()

    def test_open_tabs_hosts_and_titles_only(self):
        tabs = identify.open_tabs(self.home)
        lw = [t for t in tabs if t["browser"] == "LibreWolf"]
        self.assertEqual([(t["host"], t["title"]) for t in lw], [("www.virustotal.com", "VirusTotal - File - abc")])
        self.assertNotIn("secret", json.dumps(tabs))  # never the full URL
        self.assertAlmostEqual(lw[0]["last_accessed"], 1761900000.0)
        recent = [t for t in tabs if t["kind"] == "recent"]
        self.assertEqual([(t["browser"], t["host"]) for t in recent], [("Chromium", "docs.python.org")])

    def test_hsts(self):
        self.assertEqual(identify.hsts_hosts(self.home), {"www.virustotal.com", "example.net"})


class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS / "synthetic.pem", TLS / "synthetic.key")
        ctx.set_alpn_protocols(["h2"])
        cls.srv = socket.socket()
        cls.srv.bind(("127.0.0.1", 0))
        cls.srv.listen()
        cls.port = cls.srv.getsockname()[1]

        def serve():
            while True:
                try:
                    c, _ = cls.srv.accept()
                except OSError:
                    return
                try:
                    s = ctx.wrap_socket(c, server_side=True)
                    s.close()
                except (ssl.SSLError, OSError):
                    c.close()
        threading.Thread(target=serve, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_parse_certificate(self):
        c = identify.parse_cert(ssl.PEM_cert_to_DER_cert((TLS / "synthetic.pem").read_text()))
        self.assertEqual(c["subject"]["CN"], "vigil-test.invalid")
        self.assertEqual(c["san"], ["vigil-test.invalid", "*.vigil-test.invalid"])
        self.assertEqual(c["san_ips"], ["127.0.0.1"])
        self.assertEqual((c["key"], c["key_detail"], c["self_signed"]), ("EC", "P-256", True))
        self.assertEqual(c["sig_alg"], "ECDSA with SHA-256")

    def test_parses_every_system_ca(self):
        import glob
        n = 0
        for f in glob.glob("/etc/ssl/certs/*.pem")[:300]:
            identify.parse_cert(ssl.PEM_cert_to_DER_cert(Path(f).read_text()))
            n += 1
        if not n:
            self.skipTest("no system CA directory")

    def test_probe_and_badges(self):
        t = identify.tls_probe("127.0.0.1", self.port, sni="www.vigil-test.invalid")
        self.assertEqual(t["version"], "TLSv1.3")
        self.assertEqual(t["alpn"], "h2")
        self.assertIs(t["trusted"], False)
        self.assertIn("self-signed", t["trust_error"])
        labels = {b["label"]: b["level"] for b in identify.tls_badges(t)}
        self.assertEqual(labels["TLS 1.3"], "good")
        self.assertEqual(labels["Forward secrecy"], "good")
        self.assertEqual(labels["Untrusted certificate"], "bad")
        self.assertEqual(labels["Self-signed"], "bad")
        self.assertEqual(labels["ECDSA P-256"], "good")
        self.assertNotIn("Name mismatch", labels)  # *.vigil-test.invalid covers www.
        self.assertEqual(identify.summary_level(identify.tls_badges(t)), "bad")

    def test_unreachable(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        t = identify.tls_probe("127.0.0.1", port, timeout=1)
        self.assertIn("error", t)
        self.assertEqual(identify.tls_badges(t)[0]["label"], "TLS handshake failed")

    def test_badge_rules(self):
        now = time.time()
        cert = {"subject": {"CN": "a"}, "issuer": {"CN": "b"}, "self_signed": False, "not_before": now - 10,
                "not_after": now - 86400 * 3, "san": ["a.example"], "level": "EV", "sct": True,
                "must_staple": False, "key": "RSA", "key_detail": "1024 bit", "sig_alg": "SHA-1 with RSA"}
        t = {"version": "TLSv1", "cipher": "AES256-SHA", "bits": 256, "trusted": True, "verified_as": "b.example",
             "sni": "b.example", "cert": cert}
        labels = {b["label"]: b["level"] for b in identify.tls_badges(t, hsts=True, now=now)}
        for label, level in {"TLS 1": "bad", "Weak cipher": "warn", "No forward secrecy": "warn", "Expired": "bad",
                             "RSA 1024": "bad", "Weak signature": "bad", "Name mismatch": "bad",
                             "Extended validation": "info", "Certificate Transparency": "good", "HSTS": "good"}.items():
            self.assertEqual(labels.get(label), level, label)

    def test_name_matching(self):
        self.assertTrue(identify.name_matches("www.virustotal.com", "*.virustotal.com"))
        self.assertFalse(identify.name_matches("a.b.virustotal.com", "*.virustotal.com"))
        self.assertFalse(identify.name_matches("virustotal.com", "*.virustotal.com"))

    def test_transport(self):
        self.assertEqual(identify.transport("udp", 443)["label"], "QUIC")
        self.assertEqual(identify.transport("tcp", 80)["level"], "warn")
        self.assertEqual(identify.transport("tcp", 23)["level"], "bad")


class IdentifyEndpointTests(unittest.TestCase):
    def setUp(self):
        from vigil import server
        from .helpers import make_proc
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = server.App(f"{self.tmp.name}/data", interval=60, proc_root=make_proc(self.tmp.name),
                              start_monitor=False)
        self.addCleanup(self.app.store.close)
        self.app.monitor.poll_once()

    def test_identify_matches_tabs_and_skips_listed_addresses(self):
        g = self.app.api_graph({"scopes": "reserved"})  # the fixture uses documentation ranges
        https = [d["ip"] for d in g["destinations"] if "tcp/443" in d["ports"]]
        self.assertTrue(https)
        ip = https[0]
        tabs = [{"browser": "LibreWolf", "profile": "p", "host": "www.virustotal.com", "scheme": "https",
                 "title": "VirusTotal - File", "last_accessed": 1.0, "kind": "tab"}]
        probe = {"ip": ip, "version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "bits": 128, "alpn": "h2",
                 "trusted": True, "verified_as": "www.virustotal.com", "sni": "www.virustotal.com",
                 "cert": {"subject": {"CN": "www.virustotal.com"}, "issuer": {"CN": "Synthetic CA"},
                          "self_signed": False, "not_before": 0, "not_after": time.time() + 86400 * 60,
                          "san": ["*.virustotal.com"], "san_ips": [], "level": "DV", "sct": True,
                          "must_staple": False, "key": "EC", "key_detail": "P-256", "sig_alg": "ECDSA with SHA-256"}}
        listed = mock.Mock(side_effect=lambda x: [{"feed": "synthetic"}] if x != ip else [])
        with mock.patch.object(identify, "open_tabs", return_value=tabs), \
                mock.patch.object(identify, "resolve", return_value={"www.virustotal.com": {ip}}), \
                mock.patch.object(identify, "hsts_hosts", return_value={"www.virustotal.com"}), \
                mock.patch.object(identify, "tls_probe", return_value=probe) as tp, \
                mock.patch.object(self.app.enricher, "intel", listed):
            out = self.app.api_identify({}, json.dumps({"scopes": ["reserved"]}).encode(), {})
        tp.assert_called_once_with(ip, 443, sni="www.virustotal.com")  # listed addresses never probed
        self.assertTrue(out["skipped_listed"])
        r = next(x for x in out["results"] if x["ip"] == ip)
        self.assertEqual(r["tabs"][0]["title"], "VirusTotal - File")
        self.assertEqual(r["tabs"][0]["via"], "dns")
        self.assertIn("HSTS", {b["label"] for b in r["badges"]})
        g = self.app.api_graph({"scopes": "reserved"})
        d = next(x for x in g["destinations"] if x["ip"] == ip)
        self.assertEqual((d["host"], d["tab"], d["security"]["level"]), ("www.virustotal.com", "VirusTotal - File", "good"))
        self.assertEqual(d["transport"][0]["label"], "HTTPS")
        detail = self.app.api_destination({"ip": ip})
        self.assertEqual(detail["identity"]["hosts"], ["www.virustotal.com", "*.virustotal.com"])


class NetworkGuardTests(unittest.TestCase):
    def test_raw_connections_only_in_identify(self):
        uses = []
        for path in sorted(Path(identify.__file__).parent.glob("*.py")):
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if re.search(r"\b(create_connection|getaddrinfo|gethostbyname|socket\.connect)\(", line):
                    uses.append(f"{path.name}:{n}")
        self.assertTrue(uses)
        self.assertTrue(all(u.startswith("identify.py") for u in uses), uses)

    def test_graph_and_detail_make_no_network_calls(self):
        from vigil import server
        from .helpers import make_proc
        with tempfile.TemporaryDirectory() as tmp:
            app = server.App(f"{tmp}/data", interval=60, proc_root=make_proc(tmp), start_monitor=False)
            app.monitor.poll_once()
            with mock.patch.object(identify, "tls_probe", side_effect=AssertionError("network")), \
                    mock.patch.object(identify, "resolve", side_effect=AssertionError("network")):
                g = app.api_graph({"scopes": "internet,lan"})
                for d in g["destinations"]:
                    app.api_destination({"ip": d["ip"]})
            app.store.close()


if __name__ == "__main__":
    unittest.main()
