"""Collector tests against the synthetic /proc fixture, plus one live check."""

import os
import socket
import struct
import sys
import tempfile
import time
import unittest

from vigil import collector
from .helpers import FIXTURES, make_proc, non_root_view


class DecodeTests(unittest.TestCase):
    def test_ipv4_little_endian(self):
        self.assertEqual(collector.decode_address("0100007F:0277", "little"), ("127.0.0.1", 631))
        # A real line captured from the build container.
        self.assertEqual(collector.decode_address("020200C0:892E", "little"), ("192.0.2.2", 35118))
        self.assertEqual(collector.decode_address("0A684FA0:01BB", "little"), ("160.79.104.10", 443))

    def test_ipv4_big_endian_host(self):
        # On a big-endian CPU the kernel prints the same address as 7F000001.
        self.assertEqual(collector.decode_address("7F000001:0277", "big"), ("127.0.0.1", 631))

    def test_ipv6_and_mapped(self):
        self.assertEqual(
            collector.decode_address("B80D0120000000000000000050000000:C738", "little"),
            ("2001:db8::50", 51000))
        self.assertEqual(
            collector.decode_address("0000000000000000FFFF00000100007F:0050", "little"),
            ("127.0.0.1", 80))
        self.assertEqual(
            collector.decode_address("00000000000000000000000001000000:0016", "little"),
            ("::1", 22))

    def test_bad_field(self):
        with self.assertRaises(ValueError):
            collector.decode_address("123:0050")


class ScopeTests(unittest.TestCase):
    def test_scopes(self):
        cases = {
            "127.0.0.1": "loopback", "::1": "loopback", "10.1.2.3": "lan", "172.20.0.1": "lan",
            "192.168.1.1": "lan", "100.64.0.1": "lan", "fd00::1": "lan",
            "169.254.1.1": "link-local", "fe80::1": "link-local", "224.0.0.251": "multicast",
            "ff02::fb": "multicast", "1.1.1.1": "internet", "2606:4700::1111": "internet",
            "198.51.100.7": "reserved", "2001:db8::1": "reserved", "0.0.0.0": "unspecified",
            "::": "unspecified",
        }
        for ip, want in cases.items():
            with self.subTest(ip=ip):
                self.assertEqual(collector.scope_of(ip), want)


class ParseTableTests(unittest.TestCase):
    def test_tcp_rows_states_and_kinds(self):
        text = (FIXTURES / "proc/net/tcp").read_text()
        rows = collector.parse_table(text, "tcp", "little")
        self.assertEqual(len(rows), 11)  # header and the malformed line are skipped
        first = rows[0]
        self.assertEqual((first["local_ip"], first["local_port"], first["state"], first["kind"]),
                         ("0.0.0.0", 22, "LISTEN", "listen"))
        tw = [r for r in rows if r["state"] == "TIME_WAIT"][0]
        self.assertEqual((tw["inode"], tw["uid"], tw["kind"]), (0, 0, "connection"))
        # Timer 03 with 0xFA0 ticks left of the fixed 60 s: closed 20 s ago at 100 Hz.
        self.assertAlmostEqual(tw["closed_ago"], 60 - 0xFA0 / os.sysconf("SC_CLK_TCK"))
        self.assertNotIn("closed_ago", rows[2])  # only TIME_WAIT sockets carry it
        syn = [r for r in rows if r["inode"] == 2009][0]
        self.assertEqual((syn["state"], syn["remote_ip"], syn["remote_port"]),
                         ("SYN_SENT", "198.51.100.20", 4444))

    def test_udp_unconnected_is_listener(self):
        text = (FIXTURES / "proc/net/udp").read_text()
        rows = collector.parse_table(text, "udp", "little")
        self.assertEqual([(r["state"], r["kind"]) for r in rows],
                         [("UNCONN", "listen"), ("ESTABLISHED", "connection")])


class NetlinkTests(unittest.TestCase):
    @staticmethod
    def diag_message(inode, acked, received, info_len=232):
        msg = bytearray(72)
        struct.pack_into("=I", msg, 68, inode)
        other = struct.pack("=HH", 8, 9) + b"\x00" * 4           # an unrelated attribute
        info = bytearray(info_len)
        if info_len >= 136:  # kernels before 4.2 send a tcp_info without the byte counters
            struct.pack_into("=QQ", info, 120, acked, received)
        attr = struct.pack("=HH", 4 + info_len, 2) + bytes(info)  # INET_DIAG_INFO
        body = bytes(msg) + other + attr
        return struct.pack("=IHHII", 16 + len(body), 20, 2, 1, 0) + body

    def test_parse_synthetic_dump(self):
        done_msg = struct.pack("=IHHII", 20, 3, 2, 1, 0) + b"\x00" * 4
        data = self.diag_message(4069, 1001, 250) + self.diag_message(4070, 5, 6) + done_msg
        counts, done = collector.parse_diag(data)
        self.assertTrue(done)
        self.assertEqual(counts, {4069: (1001, 250), 4070: (5, 6)})

    def test_old_kernel_without_byte_counters(self):
        counts, done = collector.parse_diag(self.diag_message(1, 2, 3, info_len=104))
        self.assertEqual(counts, {})
        self.assertFalse(done)

    @unittest.skipUnless(collector.tcp_byte_counts() is not None, "sock_diag netlink unavailable")
    def test_live_byte_counts(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        client = socket.create_connection(server.getsockname())
        peer, _ = server.accept()
        try:
            client.sendall(b"x" * 1000)
            got = 0
            while got < 1000:
                got += len(peer.recv(4096))
            peer.sendall(b"y" * 250)
            client.recv(4096)
            time.sleep(0.05)
            counts = collector.tcp_byte_counts()
            inode = os.fstat(peer.fileno()).st_ino
            self.assertEqual(counts[inode], (250, 1000))
        finally:
            for s in (client, peer, server):
                s.close()


class IdentityTests(unittest.TestCase):
    def test_program_identity(self):
        pi = collector.program_identity
        self.assertEqual(pi("/usr/bin/curl", ["curl", "-s", "x"], "curl"), ("/usr/bin/curl", "curl"))
        self.assertEqual(pi("/opt/a (deleted)", ["/opt/a"], "a"), ("/opt/a", "a"))
        self.assertEqual(pi("/usr/bin/python3.11", ["python3", "-u", "/srv/sync.py", "-v"], "python3"),
                         ("/usr/bin/python3.11 /srv/sync.py", "sync.py (python3.11)"))
        self.assertEqual(pi("/usr/bin/python3.11", ["python3", "-m", "http.server"], "python3"),
                         ("/usr/bin/python3.11 -m http.server", "http.server (python3.11)"))
        self.assertEqual(pi("/usr/lib/jvm/bin/java", ["java", "-Xmx1g", "-jar", "app.jar"], "java"),
                         ("/usr/lib/jvm/bin/java -jar app.jar", "app.jar (java)"))
        self.assertEqual(pi("/usr/bin/bash", ["sh", "-c", "curl x | sh"], "sh"),
                         ("/usr/bin/bash", "bash"))
        self.assertEqual(pi(None, ["/usr/bin/foo", "--x"], "foo"), ("/usr/bin/foo", "foo"))
        self.assertEqual(pi(None, [], "kworker/0:1"), ("[kworker/0:1]", "[kworker/0:1]"))


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proc = make_proc(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def by_inode(self, snap):
        return {s["inode"]: s for s in snap["sockets"] if s["inode"]}

    def test_non_root_viewer(self):
        with non_root_view(self.proc):
            snap = collector.snapshot(self.proc, now=1000.0, viewer_uid=1000)
        socks = self.by_inode(snap)
        self.assertEqual(len(snap["sockets"]), 17)
        self.assertEqual(snap["missing_tables"], [])
        self.assertEqual(socks[3002]["direction"], "in")  # accepted on listening port 22
        self.assertEqual(socks[2001]["direction"], "out")
        self.assertEqual(socks[1001]["direction"], "out")  # listeners are not connections

        ff = socks[2001]
        self.assertEqual((ff["pid"], ff["pids"], ff["program"]),
                         (4410, [4410, 4500], "/usr/lib/firefox/firefox"))
        self.assertEqual(socks[2006]["remote_ip"], "192.0.2.80")  # v4-mapped normalised
        self.assertEqual(socks[2005]["remote_ip"], "2001:db8:1::10")

        upd = socks[2003]
        self.assertEqual(upd["program"], "/usr/bin/python3.11 /home/alice/.cache/updater.py")
        self.assertEqual(snap["processes"][5120]["name"], "updater.py (python3.11)")
        self.assertEqual(socks[2010]["program"], "/usr/bin/python3.11 -m smbsync")

        agent = snap["processes"][7000]
        self.assertEqual(agent["comm"], "upd) S 1 2")
        self.assertTrue(agent["exe_deleted"])
        self.assertEqual(agent["key"], "/tmp/.x/agent")
        self.assertEqual(agent["ppid"], 5120)
        tck = os.sysconf("SC_CLK_TCK")
        self.assertAlmostEqual(agent["started"], 1793300000 + 230000 / tck)

        firefox = snap["processes"][4410]
        self.assertEqual([a["name"] for a in firefox["ancestry"]], ["gnome-shell", "systemd"])
        # Ancestor start times let the analyzer label parent → child gaps.
        self.assertAlmostEqual(firefox["ancestry"][0]["started"], 1793300000 + 3000 / tck)
        self.assertAlmostEqual(firefox["started"] - firefox["ancestry"][0]["started"],
                               (123456 - 3000) / tck, places=3)  # epoch-sized floats
        self.assertEqual(firefox["parent"], "gnome-shell")

        reasons = {i: (s["hidden"] or {}).get("reason") for i, s in socks.items()}
        for inode in (1001, 1002, 3001, 3002, 1003, 1004, 1005):
            self.assertEqual(reasons[inode], "other-user", inode)
        self.assertEqual(reasons[2004], "protected")  # our own ssh, non-dumpable
        self.assertIn("1 of your processes", socks[2004]["hidden"]["explanation"])
        self.assertIn("uid 0", socks[3001]["hidden"]["explanation"])
        tw = [s for s in snap["sockets"] if s["inode"] == 0][0]
        self.assertEqual(tw["hidden"]["reason"], "closed")
        self.assertIn("TIME_WAIT", tw["hidden"]["explanation"])
        self.assertEqual(snap["hidden_counts"], {"other-user": 7, "protected": 1, "closed": 1})
        self.assertEqual(snap["unreadable_by_uid"], {0: 4, 107: 1, 33: 1, 1000: 1})

    def test_root_viewer_sees_everything_but_closed(self):
        snap = collector.snapshot(self.proc, now=1000.0, viewer_uid=0)
        socks = self.by_inode(snap)
        self.assertEqual(snap["hidden_counts"], {"closed": 1})
        self.assertEqual(snap["processes"][socks[1003]["pid"]]["name"], "nginx")
        self.assertEqual(socks[2004]["pid"], 6000)
        self.assertEqual(socks[3001]["program"], "/usr/libexec/packagekitd")
        self.assertEqual(socks[3002]["program"], "/usr/sbin/sshd")

    def test_missing_ipv6_tables(self):
        os.remove(os.path.join(self.proc, "net/tcp6"))
        os.remove(os.path.join(self.proc, "net/udp6"))
        snap = collector.snapshot(self.proc, viewer_uid=0)
        self.assertEqual(snap["missing_tables"], ["tcp6", "udp6"])
        self.assertEqual(len(snap["sockets"]), 13)

    def test_process_exits_mid_scan(self):
        # fd/ was listed but the process is gone by the time we read its status.
        for name in ("status", "comm"):
            os.remove(os.path.join(self.proc, "5200", name))
        snap = collector.snapshot(self.proc, viewer_uid=0)
        s = self.by_inode(snap)[2010]
        self.assertIsNone(s["program"])
        self.assertEqual(s["hidden"]["reason"], "unknown")

    def test_hidepid_option(self):
        path = os.path.join(self.tmp.name, "mountinfo")
        with open(path, "w") as f:
            f.write("22 28 0:21 / /sys rw,nosuid - sysfs sysfs rw\n"
                    "23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible\n")
        self.assertEqual(collector.hidepid_option(path), "invisible")
        with open(path, "w") as f:
            f.write("23 28 0:22 / /proc rw,relatime - proc proc rw\n")
        self.assertIsNone(collector.hidepid_option(path))


@unittest.skipUnless(os.path.exists("/proc/net/tcp"), "needs a Linux /proc")
class LiveTests(unittest.TestCase):
    """Reads the real /proc of whatever machine runs the tests."""

    def test_finds_our_own_connection(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        client = socket.create_connection(server.getsockname())
        peer, _ = server.accept()
        try:
            port = server.getsockname()[1]
            snap = collector.snapshot()
            mine = [s for s in snap["sockets"] if s["kind"] == "connection" and
                    s["remote_port"] == port and s["remote_ip"] == "127.0.0.1"]
            self.assertEqual(len(mine), 1)
            self.assertEqual(mine[0]["state"], "ESTABLISHED")
            self.assertEqual(mine[0]["pid"], os.getpid())
            info = snap["processes"][os.getpid()]
            self.assertEqual(os.path.realpath(info["exe"]), os.path.realpath(sys.executable))
            listeners = [s for s in snap["sockets"] if s["kind"] == "listen" and s["local_port"] == port]
            self.assertEqual(listeners[0]["pid"], os.getpid())
        finally:
            for s in (client, peer, server):
                s.close()


if __name__ == "__main__":
    unittest.main()
