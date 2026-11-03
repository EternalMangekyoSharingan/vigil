"""Enrichment tests: feed parsing and updating, the country/ASN database, scoring hooks,
and the guarantee that nothing touches the network unless asked.

Feed and database files are SYNTHETIC (tests/fixtures/feeds, see its README). Downloads
are exercised against a local HTTP server on 127.0.0.1, never the real sources.
"""

import functools
import gzip
import hashlib
import http.server
import json
import os
import re
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from vigil.net import enrich, scoring
from vigil.net.enrich import Enricher
from vigil.net.scoring import Allowlist, Scorer
from vigil.net.store import Store, Tracker
from ..helpers import FIXTURES, proc, sock, snap

FEEDS = FIXTURES / "feeds"
FF = "/usr/lib/firefox/firefox"


class LocalFeedServer:
    """Serves tests/fixtures/feeds on 127.0.0.1 and records request headers."""

    def __enter__(self):
        seen = self.headers = []

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                seen.append(dict(self.headers))
                super().do_GET()

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), functools.partial(Handler, directory=str(FEEDS)))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class ParserTests(unittest.TestCase):
    def test_feodo_json_and_csv_agree(self):
        a = enrich.parse_feodo((FEEDS / "feodo-ipblocklist.json").read_bytes())
        b = enrich.parse_feodo((FEEDS / "feodo-ipblocklist.csv").read_bytes())
        key = lambda r: (r["indicator"], r["port"], r["label"], r["first_seen"])
        self.assertEqual([key(r) for r in a], [key(r) for r in b])
        self.assertEqual(len(a), 2)  # the invalid address is skipped
        self.assertEqual(a[0]["reference"], "https://feodotracker.abuse.ch/browse/host/198.51.100.20/")

    def test_sslbl(self):
        rows = enrich.parse_sslbl((FEEDS / "sslbl.csv").read_bytes())
        self.assertEqual([(r["indicator"], r["port"]) for r in rows],
                         [("203.0.113.70", 8443), ("198.51.100.21", 8081)])

    def test_urlhaus_hosts(self):
        rows = enrich.parse_urlhaus((FEEDS / "urlhaus.csv").read_bytes())
        self.assertEqual([(r["kind"], r["host"], r["port"]) for r in rows],
                         [("url", "198.51.100.77", None), ("url", "198.51.100.77", 8080),
                          ("url", "malware.example", None)])

    def test_garbage_yields_nothing(self):
        for parse in enrich.PARSERS.values():
            self.assertEqual(parse(b"<html>Please log in</html>"), [])


class FeedUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        self.store = Store(str(self.data / "vigil.db"))
        self.en = Enricher(self.store, self.data)

    def tearDown(self):
        self.en._close_geo()
        self.store.close()
        self.tmp.cleanup()

    def point_sources_at(self, base, **names):
        (self.data / "settings.json").write_text(json.dumps({"sources": {
            n: f"{base}/{f}" for n, f in names.items()}}))

    def test_download_parse_store(self):
        with LocalFeedServer() as srv:
            self.point_sources_at(srv.base, feodo="feodo-ipblocklist.json", sslbl="sslbl.csv",
                                  urlhaus="urlhaus.csv")
            results = self.en.update_feeds()
            self.assertTrue(all(r["ok"] for r in results), results)
            self.assertTrue(srv.headers[0]["User-Agent"].startswith("Vigil/"))
            self.assertNotIn("Auth-Key", srv.headers[0])  # only ever sent to abuse.ch
        self.assertEqual({r["name"]: r["entries"] for r in results},
                         {"feodo": 2, "sslbl": 2, "urlhaus": 3})
        st = self.en.status()
        feodo = [f for f in st["feeds"] if f["name"] == "feodo"][0]
        self.assertEqual((feodo["status"], feodo["entries"]), ("ok", 2))
        self.assertEqual(feodo["sha256"], hashlib.sha256(
            (FEEDS / "feodo-ipblocklist.json").read_bytes()).hexdigest())
        self.assertTrue((self.data / "feeds" / "feodo.dat").exists())
        hits = self.en.intel("198.51.100.77")
        self.assertEqual(len(hits), 2)
        self.assertEqual(self.en.intel("malware.example")[0]["feed"], "urlhaus")

    def test_failures_keep_previous_data(self):
        self.en.import_feed("feodo", (FEEDS / "feodo-ipblocklist.json").read_bytes(), "fixture")
        with LocalFeedServer() as srv:
            self.point_sources_at(srv.base, feodo="missing.json")
            r = self.en.update_feeds(["feodo"])[0]
        self.assertFalse(r["ok"])
        self.assertIn("HTTP 404", r["error"])
        r = self.en.update_feeds(["feodo"], fetcher=lambda url, headers: b"<html>login</html>")[0]
        self.assertIn("format may have changed", r["error"])
        self.assertEqual(len(self.en.intel("198.51.100.20")), 1)  # still there
        feodo = [f for f in self.en.status()["feeds"] if f["name"] == "feodo"][0]
        self.assertEqual((feodo["status"], feodo["entries"]), ("error", 2))

    def test_auth_key_only_for_abuse_ch(self):
        sent = {}

        def fake(url, headers):
            sent[url] = headers
            return (FEEDS / "sslbl.csv").read_bytes()

        with mock.patch.dict(os.environ, {"VIGIL_ABUSECH_KEY": "k123"}):
            self.en.update_feeds(["sslbl"], fetcher=fake)
            self.point_sources_at("https://mirror.example", sslbl="sslbl.csv")
            self.en.update_feeds(["sslbl"], fetcher=fake)
        self.assertEqual(sent[enrich.FEEDS["sslbl"]["url"]], {"Auth-Key": "k123"})
        self.assertEqual(sent["https://mirror.example/sslbl.csv"], {})

    def test_size_limit(self):
        with LocalFeedServer() as srv:
            with self.assertRaisesRegex(RuntimeError, "larger than 10 bytes"):
                enrich.fetch(f"{srv.base}/sslbl.csv", limit=10)


class GeoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        self.store = Store(str(self.data / "vigil.db"))
        self.en = Enricher(self.store, self.data)
        self.en.countries = {"CH": "Switzerland", "AU": "Australia"}

    def tearDown(self):
        self.en._close_geo()
        self.store.close()
        self.tmp.cleanup()

    def test_import_and_lookup(self):
        gz = self.data / "ip2asn.tsv.gz"
        gz.write_bytes(gzip.compress((FEEDS / "ip2asn-sample.tsv").read_bytes()))
        self.assertEqual(self.en.update_geo(path=str(gz)), {"name": "geo", "ok": True, "ranges": 5})
        g = self.en.geo("9.9.9.9")
        self.assertEqual((g["asn"], g["country"], g["country_name"], g["owner"]),
                         (64496, "CH", "Switzerland", "SYNTHETIC-NET-ONE"))
        self.assertEqual(g["range"], "9.9.9.0–9.9.9.255")
        self.assertEqual(self.en.geo("198.51.100.255")["asn"], 64500)  # end is inclusive
        self.assertIsNone(self.en.geo("203.0.113.200"))  # in a gap
        self.assertIsNone(self.en.geo("0.1.2.3"))        # "Not routed" rows are dropped
        self.assertEqual(self.en.geo("2001:db8::1")["country"], "SE")
        self.assertIsNone(self.en.geo("2001:db9::1"))
        self.assertEqual(self.en.label("198.51.100.20"), "AS64500 SYNTHETIC-DOC-NET-A · NL")
        self.assertIsNone(self.en.geo("not-an-ip"))

    def test_bad_file_keeps_old_database(self):
        self.en.update_geo(path=str(FEEDS / "ip2asn-sample.tsv"))
        bad = self.data / "bad.tsv"
        bad.write_text("nothing useful here\n")
        r = self.en.update_geo(path=str(bad))
        self.assertFalse(r["ok"])
        self.assertIn("no address ranges", r["error"])
        self.assertEqual(self.en.geo("9.9.9.9")["asn"], 64496)
        self.assertEqual(self.store.get_meta("geo")["status"], "error")

    def test_country_names_fallback(self):
        names = self.data / "iso.json"
        names.write_text(json.dumps({"3166-1": [{"alpha_2": "DE", "name": "Germany"}]}))
        self.assertEqual(enrich.load_country_names(str(names)), {"DE": "Germany"})
        self.assertEqual(enrich.load_country_names(str(self.data / "absent.json")), {})


class ScoringHookTests(unittest.TestCase):
    """Feeds and geography feeding the scorer, with synthetic connection histories."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name)
        self.store = Store(str(self.data / "vigil.db"))
        self.tracker = Tracker(self.store)
        self.en = Enricher(self.store, self.data)
        self.en.countries = {"CH": "Switzerland", "AU": "Australia"}
        self.scorer = Scorer(self.store, Allowlist(str(self.data / "allow.json")), 2)
        self.scorer.extra.append(self.en)
        self.en.import_feed("feodo", (FEEDS / "feodo-ipblocklist.json").read_bytes(), "fixture",
                            now=500)
        self.en.import_feed("urlhaus", (FEEDS / "urlhaus.csv").read_bytes(), "fixture", now=500)
        self.en.update_geo(path=str(FEEDS / "ip2asn-sample.tsv"))
        self.ff = proc(4410, FF, "firefox")
        # Baseline: firefox already talks to a C2 address and to an Australian server.
        self.base = [sock("203.0.113.66", 443, 9000, FF, 4410, local_port=30000),
                     sock("1.1.1.1", 443, 9001, FF, 4410, local_port=30001)]
        self.tracker.ingest(snap(1000, self.base, [self.ff]))

    def tearDown(self):
        self.en._close_geo()
        self.store.close()
        self.tmp.cleanup()

    def findings(self, ip):
        row = self.store.one("SELECT * FROM scores WHERE ip=?", (ip,))
        return row["score"], {f["check"]: f for f in json.loads(row["findings"])}

    def test_feed_hit_alone_alerts(self):
        self.scorer.run(now=1100)
        score, f = self.findings("203.0.113.66")
        self.assertEqual(list(f), ["threat_intel"])  # nothing else is unusual about it
        self.assertEqual(score, 80)
        self.assertEqual(f["threat_intel"]["reason"],
                         "Listed by abuse.ch Feodo Tracker as ExampleLoader; listed on port 443,"
                         " the port in use; first seen 2026-09-01 10:00:00")
        self.assertIn("feodo feed downloaded", f["threat_intel"]["data"])
        self.assertIn("2 entries", f["threat_intel"]["data"])
        self.assertEqual(self.store.one("SELECT COUNT(*) n FROM alerts")["n"], 1)

    def test_urlhaus_host_and_stale_feed(self):
        self.tracker.ingest(snap(1100, self.base + [sock("198.51.100.77", 80, 9002, FF, 4410,
                                                         local_port=30002)], [self.ff]))
        self.scorer.run(now=500 + 10 * 86400)
        _, f = self.findings("198.51.100.77")
        self.assertEqual(f["threat_intel"]["points"], 60)
        self.assertIn("hosting malware (malware_download): 2 URLs, e.g. http://198.51.100.77/bins/x.sh",
                      f["threat_intel"]["reason"])
        self.assertIn("10 days old", f["threat_intel"]["data"])

    def test_first_connection_to_a_country(self):
        new = [sock("9.9.9.9", 443, 9003, FF, 4410, local_port=30003),
               sock("1.1.1.2", 443, 9004, FF, 4410, local_port=30004)]
        self.tracker.ingest(snap(1200, self.base + new, [self.ff]))
        self.scorer.run(now=1300)
        _, f = self.findings("9.9.9.9")
        self.assertIn("rare_country", f)
        self.assertTrue(f["rare_country"]["reason"].startswith(
            "First connection from this PC to a server in Switzerland (CH), at "))
        _, f = self.findings("1.1.1.2")
        self.assertNotIn("rare_country", f)  # Australia was already seen at baseline


class ApiUpdateTests(unittest.TestCase):
    def test_update_button_path_downloads_and_rescores(self):
        from vigil.net import server
        from ..helpers import make_proc
        with tempfile.TemporaryDirectory() as tmp, LocalFeedServer() as srv:
            app = server.App(f"{tmp}/data", proc_root=make_proc(tmp), start_monitor=False)
            app.monitor.poll_once()
            Path(f"{tmp}/data/settings.json").write_text(json.dumps({"sources": {
                "feodo": f"{srv.base}/feodo-ipblocklist.csv", "sslbl": f"{srv.base}/sslbl.csv",
                "urlhaus": f"{srv.base}/urlhaus.csv", "geo": f"{srv.base}/ip2asn-sample.tsv"}}))
            res = app.api_intel_update({}, b'{"what": "feeds"}', {})
            self.assertTrue(all(r["ok"] for r in res["results"]), res)
            res = app.api_intel_update({}, b'{"what": "geo"}', {})
            self.assertEqual(res["results"][0]["ranges"], 5)
            g = app.api_graph({"scopes": "internet,lan,reserved"})
            labels = {d["ip"]: d["label"] for d in g["destinations"]}
            self.assertEqual(labels["198.51.100.30"], "AS64500 SYNTHETIC-DOC-NET-A · NL")
            # The fixture's agent connects to 198.51.100.20:4444, a listed C2.
            dest = app.api_destination({"ip": "198.51.100.20"})
            self.assertEqual(dest["enrichment"]["intel"][0]["label"], "SyntheticBot")
            checks = {f["check"] for f in dest["findings"][0]["findings"]}
            self.assertIn("threat_intel", checks)
            self.assertEqual(app.store.one("SELECT COUNT(*) n FROM alerts")["n"], 1)
            app.enricher._close_geo()
            app.store.close()


class NoNetworkTests(unittest.TestCase):
    def test_only_the_update_path_can_open_urls(self):
        # Static guarantee: urlopen appears in exactly one function in the whole suite,
        # core/netfetch.http (it moved there from enrich.py when the core was extracted;
        # enrich.fetch and enrich.http are the same functions, re-exported).
        uses = []
        pkg = Path(enrich.__file__).parent.parent
        for path in sorted(pkg.rglob("*.py")):
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if re.search(r"\burlopen\(", line):
                    uses.append(f"{path.relative_to(pkg)}:{n}")
        self.assertEqual(len(uses), 1, uses)
        self.assertTrue(uses[0].startswith("core/netfetch.py"), uses)
        self.assertEqual(enrich.http.__module__, "vigil.core.netfetch")

    def test_normal_operation_makes_no_requests(self):
        from vigil.net import server
        from ..helpers import make_proc
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("network!")), \
                mock.patch("socket.create_connection", side_effect=AssertionError("network!")):
            app = server.App(f"{tmp}/data", proc_root=make_proc(tmp), start_monitor=False)
            app.enricher.update_geo(path=str(FEEDS / "ip2asn-sample.tsv"))  # a local file
            app.monitor.poll_once()
            app.scorer.run()
            app.api_graph({"scopes": "internet,lan,reserved"})
            app.api_destination({"ip": "198.51.100.30"})
            app.api_lookup({"ip": "9.9.9.9"})
            app.api_intel_status({})
            app.enricher._close_geo()
            app.store.close()


if __name__ == "__main__":
    unittest.main()
