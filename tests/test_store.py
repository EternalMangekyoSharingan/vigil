"""Tracker and store tests, driven by synthetic snapshots."""

import os
import tempfile
import unittest

from vigil import collector
from vigil.store import Store, Tracker
from .helpers import make_proc, non_root_view, proc, sock, snap

FF = "/usr/lib/firefox/firefox"
UPD = "/usr/bin/python3.11 /home/alice/.cache/updater.py"
ALL_SCOPES = ("internet", "lan", "loopback", "reserved")


class TrackerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "vigil.db")
        self.store = Store(self.db)
        self.tracker = Tracker(self.store)
        self.ff = proc(4410, FF, "firefox")
        self.upd = proc(5120, UPD, "updater.py (python3.11)")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def events(self, kind=None):
        rows = self.store.query("SELECT * FROM events ORDER BY id")
        return [r for r in rows if kind is None or r["kind"] == kind]

    def test_lifetime_open_update_close(self):
        a = sock("198.51.100.30", 443, 2001, FF, 4410, state="SYN_SENT")
        self.tracker.ingest(snap(100, [a], [self.ff]))
        a2 = dict(a, state="ESTABLISHED")
        self.tracker.ingest(snap(102, [a2], [self.ff]))
        stats = self.tracker.ingest(snap(104, [], [self.ff]))
        self.assertEqual(stats["closed"], 1)
        row = self.store.one("SELECT * FROM connections")
        self.assertEqual((row["opened_at"], row["last_seen"], row["closed_at"], row["state"]),
                         (100, 102, 104, "ESTABLISHED"))
        self.assertEqual(self.tracker.open, {})

    def test_baseline_then_first_seen(self):
        a = sock("198.51.100.30", 443, 2001, FF, 4410)
        self.tracker.ingest(snap(100, [a], [self.ff]))
        ev = self.events("first_seen")
        self.assertEqual(len(ev), 1)
        self.assertTrue(ev[0]["summary"].startswith("Baseline: first outbound"))
        self.assertIn("/proc/net/tcp inode 2001", ev[0]["source"])
        self.assertEqual(self.store.get_meta("baseline_at"), 100)

        # Same pair again: nothing new, but the pair counter moves.
        b = sock("198.51.100.30", 443, 2002, FF, 4410, local_port=50001)
        self.tracker.ingest(snap(110, [a, b], [self.ff]))
        self.assertEqual(len(self.events("first_seen")), 1)
        pair = self.store.one("SELECT * FROM pairs WHERE program=?", (FF,))
        self.assertEqual(pair["connections"], 2)

        # Same destination, new port: first time for this pair only.
        c = sock("198.51.100.30", 8080, 2003, FF, 4410, local_port=50002)
        self.tracker.ingest(snap(120, [a, b, c], [self.ff]))
        self.assertEqual(self.events("first_seen")[-1]["summary"],
                         "First time this program used tcp 198.51.100.30:8080")

        # A new program contacting a new destination after the baseline.
        d = sock("198.51.100.7", 8443, 2004, UPD, 5120, local_port=50003)
        self.tracker.ingest(snap(130, [a, b, c, d], [self.ff, self.upd]))
        last = self.events("first_seen")[-1]
        self.assertEqual(last["summary"],
                         "First outbound connection seen for this program (tcp 198.51.100.7:8443)")
        self.assertIn('"destination_new": true', last["detail"])
        self.assertIn('"baseline": false', last["detail"])
        prog = self.store.one("SELECT * FROM programs WHERE key=?", (UPD,))
        self.assertEqual(prog["first_outbound"], 130)

        # An existing program reaching a destination nobody has used before.
        e = sock("203.0.113.5", 443, 2005, FF, 4410, local_port=50004)
        self.tracker.ingest(snap(140, [a, b, c, d, e], [self.ff, self.upd]))
        self.assertEqual(self.events("first_seen")[-1]["summary"],
                         "New destination for this PC: tcp 203.0.113.5:443 (reserved)")

    def test_time_wait_tail_is_not_a_new_connection(self):
        a = sock("198.51.100.30", 443, 2001, FF, 4410)
        self.tracker.ingest(snap(100, [a], [self.ff]))
        tail = sock("198.51.100.30", 443, 0, uid=0, state="TIME_WAIT")
        self.tracker.ingest(snap(102, [tail], [self.ff]))
        rows = self.store.query("SELECT * FROM connections")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["closed_at"], 102)

    def test_unseen_time_wait_is_tracked_as_closed_before_attribution(self):
        self.tracker.ingest(snap(100, [], []))
        tw = sock("198.51.100.30", 80, 0, uid=0, state="TIME_WAIT", local_port=51200)
        self.tracker.ingest(snap(102, [tw], []))
        row = self.store.one("SELECT * FROM connections")
        self.assertEqual(row["program"], "hidden:closed")
        prog = self.store.one("SELECT * FROM programs WHERE key='hidden:closed'")
        self.assertEqual((prog["hidden"], prog["name"]), (1, "Closed before attribution"))
        # Hidden pseudo-programs never get a "first outbound" claim.
        self.assertIsNone(prog["first_outbound"])

    def test_other_user_sockets_grouped_per_uid(self):
        h0 = sock("203.0.113.9", 443, 3001, uid=0)
        h33 = sock("203.0.113.9", 443, 3002, uid=33, local_port=50010)
        self.tracker.ingest(snap(100, [h0, h33], []))
        keys = {r["program"] for r in self.store.query("SELECT program FROM connections")}
        self.assertEqual(keys, {"hidden:other-user:0", "hidden:other-user:33"})

    def test_inbound_connections_keyed_by_service_port(self):
        sshd = proc(812, "/usr/sbin/sshd", "sshd", uid=0, user="root")
        self.tracker.ingest(snap(100, [], [sshd]))
        a = sock("203.0.113.50", 60000, 3002, "/usr/sbin/sshd", 812, local_port=22, uid=0,
                 direction="in")
        b = sock("203.0.113.50", 60001, 3003, "/usr/sbin/sshd", 812, local_port=22, uid=0,
                 direction="in")
        self.tracker.ingest(snap(110, [a, b], [sshd]))
        pair = self.store.one("SELECT * FROM pairs")
        self.assertEqual((pair["port"], pair["direction"], pair["connections"]), (22, "in", 2))
        ev = self.events("first_seen")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["summary"], "New address for this PC: 203.0.113.50 (reserved)"
                                           " connected in to tcp port 22")
        # Accepting a connection is not the program reaching out.
        prog = self.store.one("SELECT * FROM programs WHERE key='/usr/sbin/sshd'")
        self.assertIsNone(prog["first_outbound"])
        g = self.tracker.graph(now=110, window=900, scopes=ALL_SCOPES)
        self.assertEqual(g["edges"][0]["ports"][0]["port"], 22)
        self.assertEqual(g["destinations"][0]["ports"], ["tcp/22 in"])
        items = self.tracker.timeline(program="/usr/sbin/sshd")
        self.assertIn("203.0.113.50:60000 → 192.168.1.50:22 (inbound)",
                      [i for i in items if i["kind"] == "open"][-1]["summary"])

    def test_listen_event_after_baseline_only(self):
        l1 = sock("0.0.0.0", 0, 1001, FF, 4410, kind="listen", state="LISTEN", local_ip="0.0.0.0",
                  local_port=8080)
        self.tracker.ingest(snap(100, [l1], [self.ff]))
        self.assertEqual(self.events("listen"), [])
        l2 = sock("0.0.0.0", 0, 1002, FF, 4410, kind="listen", state="LISTEN", local_ip="0.0.0.0",
                  local_port=4444)
        self.tracker.ingest(snap(110, [l1, l2], [self.ff]))
        ev = self.events("listen")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["summary"], "firefox started listening on tcp port 4444 (all interfaces)")
        self.assertEqual([r["local_port"] for r in self.tracker.listeners()], [4444, 8080])

    def test_restart_continues_and_closes(self):
        a = sock("198.51.100.30", 443, 2001, FF, 4410)
        b = sock("198.51.100.31", 443, 2002, FF, 4410, local_port=50001)
        self.tracker.ingest(snap(100, [a, b], [self.ff]))
        self.tracker.ingest(snap(102, [a, b], [self.ff]))
        # Vigil stops; b closes while it is down; Vigil starts again.
        t2 = Tracker(self.store)
        t2.ingest(snap(500, [a], [self.ff]))
        rows = {r["inode"]: r for r in self.store.query("SELECT * FROM connections")}
        self.assertEqual(len(rows), 2)
        self.assertIsNone(rows[2001]["closed_at"])
        self.assertEqual(rows[2001]["opened_at"], 100)  # same connection, not a new one
        self.assertEqual(rows[2002]["closed_at"], 102)
        self.assertEqual(rows[2002]["close_note"], "closed while Vigil was stopped")
        # After the resume poll, closes are timed normally again.
        t2.ingest(snap(502, [], [self.ff]))
        self.assertEqual(self.store.one("SELECT closed_at FROM connections WHERE inode=2001")["closed_at"],
                         502)

    def test_graph_aggregates_and_filters(self):
        socks = [
            sock("198.51.100.30", 443, 2001, FF, 4410),
            sock("198.51.100.30", 80, 2002, FF, 4410, local_port=50001),
            sock("192.168.1.1", 53, 2003, UPD, 5120, proto="udp", local_port=50002),
            sock("127.0.0.1", 631, 2004, FF, 4410, local_ip="127.0.0.1", local_port=50003),
        ]
        self.tracker.ingest(snap(100, socks, [self.ff, self.upd]))
        self.tracker.ingest(snap(200, socks[:1] + socks[2:], [self.ff, self.upd]))  # :80 closes
        g = self.tracker.graph(now=210, window=900, scopes=ALL_SCOPES)
        edges = {(e["program"], e["ip"]): e for e in g["edges"]}
        ff = edges[(FF, "198.51.100.30")]
        self.assertEqual((ff["live"], ff["total"]), (1, 2))
        self.assertEqual(sorted(p["port"] for p in ff["ports"]), [80, 443])
        self.assertEqual({d["ip"]: d["ports"] for d in g["destinations"]}["198.51.100.30"],
                         ["tcp/80", "tcp/443"])
        progs = {p["key"]: p for p in g["programs"]}
        self.assertEqual(progs[FF]["destinations"], 2)
        self.assertEqual(progs[FF]["info"]["pid"], 4410)

        lan_only = self.tracker.graph(now=210, window=900, scopes=("lan",))
        self.assertEqual([e["ip"] for e in lan_only["edges"]], ["192.168.1.1"])
        # Live-only window drops the closed :80 connection but keeps live ones.
        live = self.tracker.graph(now=210, window=0, scopes=ALL_SCOPES)
        ff_live = [e for e in live["edges"] if e["ip"] == "198.51.100.30"][0]
        self.assertEqual([p["port"] for p in ff_live["ports"]], [443])

    def test_timeline_has_sources(self):
        a = sock("198.51.100.30", 443, 2001, FF, 4410)
        self.tracker.ingest(snap(100, [a], [self.ff]))
        self.tracker.ingest(snap(160, [], [self.ff]))
        items = self.tracker.timeline(program=FF)
        kinds = [i["kind"] for i in items]
        self.assertEqual(kinds, ["close", "first_seen", "open"])
        self.assertIn("open ≥ 1m 0s", items[0]["summary"])
        for i in items:
            self.assertIn("/proc/net/tcp inode 2001", i["source"])
        dest = self.tracker.destination_detail("198.51.100.30")
        self.assertEqual(dest["pairs"][0]["name"], "firefox")
        self.assertEqual(len(dest["timeline"]), 3)
        self.assertIsNone(self.tracker.program_detail("nope"))

    def test_prune_keeps_open_and_recent(self):
        a = sock("198.51.100.30", 443, 2001, FF, 4410)
        b = sock("198.51.100.31", 443, 2002, FF, 4410, local_port=50001)
        self.tracker.ingest(snap(100, [a, b], [self.ff]))
        self.tracker.ingest(snap(200, [a], [self.ff]))
        removed = self.store.prune(now=200 + 15 * 86400, keep_days=14)
        self.assertEqual(removed, 1)
        self.assertEqual(len(self.store.query("SELECT * FROM connections")), 1)
        self.assertEqual(len(self.store.query("SELECT * FROM pairs")), 2)  # first-seen kept


class FixtureEndToEndTests(unittest.TestCase):
    """The synthetic /proc fixture through collector and tracker together."""

    def test_fixture_into_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = make_proc(tmp)
            store = Store(os.path.join(tmp, "v.db"))
            tracker = Tracker(store)
            with non_root_view(proc_root):
                tracker.ingest(collector.snapshot(proc_root, now=1000.0, viewer_uid=1000))
            g = tracker.graph(now=1000.0, window=900, scopes=ALL_SCOPES)
            names = {p["name"] for p in g["programs"]}
            self.assertEqual(names, {
                "firefox", "updater.py (python3.11)", "smbsync (python3.11)", "agent",
                "Closed before attribution", "Hidden: protected process", "Hidden: root"})
            agent = [p for p in g["programs"] if p["name"] == "agent"][0]
            self.assertTrue(agent["info"]["exe_deleted"])
            self.assertEqual(agent["info"]["parent"], "python3")  # Name: line of pid 5120
            listeners = {(r["program"], r["local_port"]) for r in tracker.listeners()}
            self.assertIn(("hidden:other-user:0", 22), listeners)
            self.assertIn(("hidden:other-user:107", 5353), listeners)
            self.assertEqual(len(tracker.listeners()), 5)
            store.close()


if __name__ == "__main__":
    unittest.main()
