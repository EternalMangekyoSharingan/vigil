"""Vigil as a desktop app: its own window and menu entry, no browser tabs or toolbars.

No new dependency. The window comes from the best thing already on the machine:

1. a native window from WebKitGTK, when PyGObject and WebKit2GTK are installed
   (they are on most GNOME desktops);
2. an installed Chromium-family browser in --app mode, with its own private
   profile under the data directory and its background networking switched off;
3. otherwise the default browser, as a plain tab.

The server stays on 127.0.0.1 and stops when the window closes. A per-data-directory
lock keeps two Vigils from polling into one database: opening the app while Vigil
is already running opens a window onto the running one.
"""

import fcntl
import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ICON = REPO / "static" / "icon.svg"
CHROMIUMS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
             "brave-browser", "brave", "microsoft-edge", "microsoft-edge-stable", "vivaldi-stable",
             "vivaldi")
# Keep the app window quiet: no sync, extensions, updates or other background traffic.
CHROMIUM_FLAGS = ("--no-first-run", "--no-default-browser-check", "--disable-extensions",
                  "--disable-sync", "--disable-background-networking", "--disable-component-update",
                  "--disable-default-apps", "--disable-features=Translate,MediaRouter,OptimizationHints",
                  "--class=Vigil", "--window-size=1440,900")
QUICK_EXIT = 3.0  # a browser that returns this fast handed the window to a running instance


# ---- one Vigil per data directory ----------------------------------------------------

class DataLock:
    """An flock on <data>/vigil.lock, with the serving port written beside it."""

    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.fh = None

    def acquire(self):
        self.fh = open(self.dir / "vigil.lock", "a+")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            self.fh.close()
            self.fh = None
            return False

    def publish(self, port):
        (self.dir / "vigil.port").write_text(str(port))

    def running_port(self):
        try:
            return int((self.dir / "vigil.port").read_text().strip())
        except (OSError, ValueError):
            return None

    def release(self):
        if self.fh:
            try:
                (self.dir / "vigil.port").unlink()
            except OSError:
                pass
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()
            self.fh = None


# ---- windows -------------------------------------------------------------------------

def find_chromium(which=shutil.which, env=os.environ):
    """VIGIL_BROWSER if set, else the first Chromium-family browser on PATH."""
    if env.get("VIGIL_BROWSER"):
        return env["VIGIL_BROWSER"]
    for name in CHROMIUMS:
        path = which(name)
        if path:
            return path
    return None


def chromium_command(binary, url, profile_dir):
    return [binary, f"--app={url}", f"--user-data-dir={profile_dir}", *CHROMIUM_FLAGS]


def native_window(url, title="Vigil"):
    """Show url in a WebKitGTK window; returns False if GTK/WebKit are unavailable."""
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        try:
            gi.require_version("WebKit2", "4.1")
        except ValueError:
            gi.require_version("WebKit2", "4.0")
        from gi.repository import Gtk, WebKit2
    except Exception:  # not installed, wrong versions, or a broken binding
        return False
    win = Gtk.Window(title=title)
    win.set_default_size(1440, 900)
    try:
        win.set_icon_from_file(str(ICON))
    except Exception:
        pass
    view = WebKit2.WebView()
    view.load_uri(url)
    win.add(view)
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    Gtk.main()
    return True


def wait_for_interrupt(message):
    print(message)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


def open_window(url, data_dir, mode="auto", popen=subprocess.Popen, which=shutil.which,
                env=os.environ, browser_open=webbrowser.open, wait=wait_for_interrupt):
    """Open url as an app window and block until it closes. Returns how it was shown."""
    if mode in ("auto", "native") and native_window(url):
        return "native"
    if mode == "native":
        raise SystemExit("No WebKitGTK window available (install PyGObject and WebKit2GTK), "
                         "or use --window chromium / browser.")
    if mode in ("auto", "chromium"):
        binary = find_chromium(which, env)
        if binary:
            profile = Path(data_dir) / "app-profile"
            profile.mkdir(parents=True, exist_ok=True, mode=0o700)
            started = time.monotonic()
            proc = popen(chromium_command(binary, url, profile),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                return "chromium"
            if time.monotonic() - started < QUICK_EXIT:
                wait(f"The window opened in an already running {Path(binary).name}. Vigil keeps "
                     f"running until you press Ctrl+C.")
            return "chromium"
        if mode == "chromium":
            raise SystemExit("No Chromium-family browser found. Set VIGIL_BROWSER to its path.")
    browser_open(url)
    wait(f"Opened {url} in your browser. Vigil keeps running until you press Ctrl+C.")
    return "browser"


def run(data_dir, port=0, interval=2.0, mode="auto", opener=open_window):
    """Start Vigil (or join the one already running) and show it in its own window."""
    from .server import HOST, App, make_server

    lock = DataLock(data_dir)
    if not lock.acquire():
        running = lock.running_port()
        if not running:
            raise SystemExit(f"Another Vigil is starting with {data_dir}; try again in a moment.")
        print(f"Vigil is already running; opening a window onto it (port {running}).")
        return opener(f"http://{HOST}:{running}/", data_dir, mode)
    try:
        httpd = make_server(None, port)
    except OSError as exc:
        lock.release()
        raise SystemExit(f"Cannot listen on {HOST}:{port}: {exc.strerror}.") from None
    app = httpd.app = App(data_dir, interval)
    lock.publish(httpd.server_address[1])
    threading.Thread(target=httpd.serve_forever, name="vigil-http", daemon=True).start()
    url = f"http://{HOST}:{httpd.server_address[1]}/"
    try:
        return opener(url, data_dir, mode)
    finally:
        app.monitor.stop()
        httpd.shutdown()
        httpd.server_close()
        app.store.close()
        lock.release()


# ---- menu entry (per user, no root) ----------------------------------------------------

def _quote(arg):
    """Quote one Exec argument as the Desktop Entry spec asks."""
    if any(c in arg for c in ' \t\n"\'\\><~|&;$*?#()`'):
        return '"' + "".join("\\" + c if c in '"`$\\' else c for c in arg) + '"'
    return arg


def desktop_entry(python=sys.executable, repo=REPO, data_dir=None):
    exec_args = [python, "-m", "vigil"] + (["--data", str(data_dir)] if data_dir else []) + ["app"]
    return "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        "Version=1.5",
        "Name=Vigil",
        "GenericName=Network and file inspector",
        "Comment=See which programs talk to whom, and what a file would do",
        "Exec=" + " ".join(_quote(a) for a in exec_args),
        f"Path={repo}",
        "Icon=vigil",
        "Terminal=false",
        "Categories=Network;Security;System;Monitor;",
        "Keywords=network;security;connections;malware;beacon;",
        "StartupNotify=true",
        "StartupWMClass=Vigil",
        "",
    ])


def data_home(env=os.environ):
    return Path(env.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")


def install_launcher(data_dir=None, home=None):
    """Add Vigil to the desktop's application menu, for this user only."""
    base = Path(home) if home else data_home()
    entry = base / "applications" / "vigil.desktop"
    icon = base / "icons" / "hicolor" / "scalable" / "apps" / "vigil.svg"
    entry.parent.mkdir(parents=True, exist_ok=True)
    icon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ICON, icon)
    entry.write_text(desktop_entry(data_dir=data_dir))
    return entry, icon


def uninstall_launcher(home=None):
    base = Path(home) if home else data_home()
    removed = []
    for path in (base / "applications" / "vigil.desktop",
                 base / "icons" / "hicolor" / "scalable" / "apps" / "vigil.svg"):
        if path.exists():
            path.unlink()
            removed.append(path)
    return removed
