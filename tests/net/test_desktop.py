"""Desktop shell tests: finding a window, the server's lifetime around it, the menu entry."""

import configparser
import http.client
import os
import tempfile
import unittest
from pathlib import Path

from vigil.net import desktop


class FakeProc:
    def __init__(self, cmd, **kw):
        self.cmd = cmd

    def wait(self):
        return 0

    def terminate(self):
        pass


class WindowTests(unittest.TestCase):
    def test_find_chromium(self):
        have = {"google-chrome": "/usr/bin/google-chrome", "brave-browser": "/usr/bin/brave-browser"}
        self.assertEqual(desktop.find_chromium(have.get, env={}), "/usr/bin/google-chrome")
        self.assertIsNone(desktop.find_chromium({}.get, env={}))
        self.assertEqual(desktop.find_chromium({}.get, env={"VIGIL_BROWSER": "/opt/x/chrome"}), "/opt/x/chrome")

    def test_app_mode_command(self):
        cmd = desktop.chromium_command("/usr/bin/chromium", "http://127.0.0.1:8765/", "/d/app-profile")
        self.assertEqual(cmd[:3], ["/usr/bin/chromium", "--app=http://127.0.0.1:8765/",
                                   "--user-data-dir=/d/app-profile"])
        self.assertIn("--disable-background-networking", cmd)
        self.assertFalse([c for c in cmd if "remote-debugging" in c or "no-sandbox" in c])

    def test_chromium_window_blocks_until_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []

            def popen(cmd, **kw):
                calls.append(cmd)
                return FakeProc(cmd)

            waited = []
            how = desktop.open_window("http://127.0.0.1:1/", tmp, mode="chromium", popen=popen,
                                      which={"chromium": "/usr/bin/chromium"}.get, env={},
                                      wait=waited.append)
            self.assertEqual(how, "chromium")
            self.assertTrue(calls[0][1].startswith("--app="))
            self.assertTrue((Path(tmp) / "app-profile").is_dir())
            # The fake browser "closes" instantly, which looks like a hand-off to a
            # running browser: Vigil keeps serving until interrupted.
            self.assertIn("already running", waited[0])

    def test_falls_back_to_the_default_browser(self):
        opened, waited = [], []
        how = desktop.open_window("http://127.0.0.1:1/", "/nonexistent", mode="auto",
                                  which={}.get, env={}, browser_open=opened.append,
                                  wait=waited.append)
        self.assertEqual(how, "browser")
        self.assertEqual(opened, ["http://127.0.0.1:1/"])
        with self.assertRaises(SystemExit):
            desktop.open_window("u", "/nonexistent", mode="chromium", which={}.get, env={})


class RunTests(unittest.TestCase):
    def test_server_lives_exactly_as_long_as_the_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            seen = {}

            def opener(url, data_dir, mode):
                port = int(url.rsplit(":", 1)[1].strip("/"))
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/api/status", headers={"Host": f"127.0.0.1:{port}"})
                seen["status"] = conn.getresponse().status
                conn.close()
                seen["port"] = port
                seen["published"] = (Path(data_dir) / "vigil.port").read_text()
                # A second start on the same data joins this one instead of polling twice.
                seen["second"] = desktop.run(data_dir, opener=lambda u, d, m: u)
                return "test"

            self.assertEqual(desktop.run(tmp, opener=opener), "test")
            self.assertEqual(seen["status"], 200)
            self.assertEqual(seen["published"], str(seen["port"]))
            self.assertEqual(seen["second"], f"http://127.0.0.1:{seen['port']}/")
            with self.assertRaises(OSError):  # stopped once the window closed
                c = http.client.HTTPConnection("127.0.0.1", seen["port"], timeout=2)
                c.request("GET", "/")
                c.getresponse()
            self.assertFalse((Path(tmp) / "vigil.port").exists())
            lock = desktop.DataLock(tmp)
            self.assertTrue(lock.acquire())  # released
            lock.release()


class LauncherTests(unittest.TestCase):
    def test_install_and_uninstall(self):
        with tempfile.TemporaryDirectory() as home:
            entry, icon = desktop.install_launcher(home=home)
            self.assertEqual(entry, Path(home) / "applications" / "vigil.desktop")
            self.assertEqual(icon.read_bytes(), desktop.ICON.read_bytes())
            cp = configparser.ConfigParser(interpolation=None)
            cp.optionxform = str
            cp.read(entry)
            e = cp["Desktop Entry"]
            self.assertEqual((e["Type"], e["Name"], e["Icon"], e["Terminal"]), ("Application", "Vigil", "vigil", "false"))
            self.assertTrue(e["Exec"].endswith("-m vigil app"))
            self.assertEqual(e["Path"], str(desktop.REPO))
            self.assertEqual(len(desktop.uninstall_launcher(home=home)), 2)
            self.assertFalse(entry.exists())

    def test_exec_quoting(self):
        text = desktop.desktop_entry(python="/opt/my python/bin/python3", data_dir="/data dir")
        line = [l for l in text.splitlines() if l.startswith("Exec=")][0]
        self.assertEqual(line, 'Exec="/opt/my python/bin/python3" -m vigil --data "/data dir" app')

    def test_xdg_data_home(self):
        self.assertEqual(desktop.data_home({"XDG_DATA_HOME": "/x/share"}), Path("/x/share"))
        self.assertTrue(str(desktop.data_home({})).endswith(os.path.join(".local", "share")))


if __name__ == "__main__":
    unittest.main()
