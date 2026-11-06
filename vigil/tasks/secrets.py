"""Which running programs have your secrets open: SSH keys, browser passwords and cookies,
password-manager databases, wallets, cloud and chat tokens.

Infostealers do one thing: open these files and copy them out. The program that owns a
store (Firefox for key4.db, ssh-agent for a key) holding it open is normal; anything else
is worth a look. Read from /proc/<pid>/fd with readlink only: no file is opened.

Without root, Vigil can read the open files of your own processes only. That is the case
that matters here (your secrets are readable by programs running as you), and the count of
processes it could not look into is reported, not hidden.
"""

import os
import re

# kind: (what to call it, path pattern, programs that normally hold it, ATT&CK)
BROWSERS_CHROMIUM = {"chrome", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave",
                     "brave-browser", "msedge", "microsoft-edge", "opera", "vivaldi", "vivaldi-bin", "thorium",
                     "yandex_browser", "electron", "chrome_crashpad_handler", "code", "codium", "slack", "signal-desktop",
                     "spotify", "obsidian", "teams-for-linux"}
BROWSERS_GECKO = {"firefox", "firefox-bin", "firefox-esr", "librewolf", "waterfox", "floorp", "zen", "zen-bin",
                  "thunderbird", "thunderbird-bin", "betterbird", "seamonkey", "icecat", "mullvadbrowser"}
SSH = {"ssh", "ssh-agent", "ssh-add", "ssh-keygen", "sshd", "gpg-agent", "gnome-keyring-daemon", "seahorse",
       "keepassxc", "ksshaskpass", "kwalletd5", "kwalletd6", "scp", "sftp", "git", "mosh-client", "autossh"}
GPG = {"gpg", "gpg2", "gpg-agent", "gpgsm", "scdaemon", "kleopatra", "seahorse", "keyboxd"}
VAULTS = {"keepassxc", "keepass", "keepass2", "keeweb", "kpcli", "mono", "secrets", "gnome-passwords", "passwordsafe"}
KEYRINGS = {"gnome-keyring-daemon", "kwalletd5", "kwalletd6", "seahorse", "kwalletmanager5", "kwalletmanager",
            "secret-tool"}
CHAT = {"discord", "Discord", "discord-canary", "discordcanary", "discord-ptb", "vesktop", "webcord", "electron",
        "armcord", "legcord", "telegram-desktop", "Telegram", "element-desktop"}
WALLETS = {"bitcoind", "bitcoin-qt", "electrum", "exodus", "Exodus", "monero-wallet-gui", "monerod", "geth",
           "ledger-live", "ledger-live-desktop", "sparrow", "wasabi", "feather"}
CLOUD = {"aws", "kubectl", "k9s", "helm", "docker", "dockerd", "podman", "gcloud", "az", "terraform", "lens",
         "openlens", "git", "git-credential-libsecret", "git-credential-store", "psql", "curl"}
# Programs that read everything by design: backups, sync, indexers. Holding a secret is expected.
READERS = {"borg", "restic", "rsync", "rclone", "duplicity", "deja-dup", "kopia", "tar", "syncthing", "dropbox",
           "nextcloud", "owncloud", "megasync", "baloo_file", "baloo_file_extractor", "tracker-miner-fs-3",
           "tracker-extract-3", "localsearch-3", "updatedb", "plocate", "mlocate", "clamscan", "clamd", "rkhunter",
           "timeshift", "snapper", "btrbk", "pika-backup", "vorta", "back-in-time", "backintime"}
EDITORS = {"vim", "nvim", "vi", "nano", "emacs", "micro", "helix", "hx", "kate", "gedit", "gnome-text-editor",
           "mousepad", "code", "codium", "zed", "subl", "less", "more", "bat", "cat", "view"}

KINDS = {
    "ssh_key": ("an SSH private key", re.compile(r"/\.ssh/(id_[a-z0-9_-]+|[^/]+_key|[^/]+\.pem)$"), SSH, ["T1552.004"]),
    "gpg_key": ("GnuPG private keys", re.compile(r"/\.gnupg/(private-keys-v1\.d/|secring\.gpg$)"), GPG, ["T1552.004"]),
    "browser_passwords": ("saved browser passwords",
                          re.compile(r"/(Login Data|Login Data For Account|logins\.json|key4\.db|key3\.db|signons\.sqlite)$"),
                          BROWSERS_CHROMIUM | BROWSERS_GECKO, ["T1555.003"]),
    "browser_cookies": ("browser cookies (logged-in sessions)", re.compile(r"/(Cookies|cookies\.sqlite|Network/Cookies)$"),
                        BROWSERS_CHROMIUM | BROWSERS_GECKO, ["T1539"]),
    "browser_keys": ("the browser's encryption key", re.compile(r"/(Local State|Web Data)$"), BROWSERS_CHROMIUM,
                     ["T1555.003"]),
    "password_db": ("a password database", re.compile(r"\.(kdbx|kdb|psafe3|1pif)$"), VAULTS, ["T1555.005"]),
    "keyring": ("the desktop keyring", re.compile(r"/(\.local/share/keyrings/[^/]+\.keyring|\.local/share/kwalletd/[^/]+\.kwl)$"),
                KEYRINGS, ["T1555"]),
    "chat_token": ("a chat app's login token", re.compile(r"/(discord[a-z]*|Discord|vesktop|WebCord|armcord|legcord)/"
                                                          r"Local Storage/leveldb/"), CHAT, ["T1528"]),
    "wallet": ("a cryptocurrency wallet", re.compile(r"/(\.bitcoin/(wallets/.*|wallet\.dat)|\.electrum/wallets/|"
                                                     r"\.config/Exodus/exodus\.wallet/|\.ethereum/keystore/|"
                                                     r"\.monero/|Ledger Live/|\.sparrow/wallets/)"), WALLETS, ["T1005"]),
    "cloud_creds": ("cloud or developer credentials",
                    re.compile(r"/(\.aws/credentials|\.kube/config|\.docker/config\.json|\.netrc|\.git-credentials|"
                               r"\.pgpass|\.config/gcloud/(credentials\.db|access_tokens\.db|application_default_credentials\.json)|"
                               r"\.azure/(msal_token_cache\.json|accessTokens\.json)|\.config/gh/hosts\.yml)$"),
                    CLOUD, ["T1552.001"]),
}


def open_files(proc_root, pid, limit=4096):
    """Paths this process has open (readlink on its fd links), or None if not readable."""
    d = os.path.join(proc_root, str(pid), "fd")
    try:
        names = os.listdir(d)
    except OSError:
        return None
    out = []
    for n in names[:limit]:
        try:
            t = os.readlink(os.path.join(d, n))
        except OSError:
            continue
        if t.startswith("/"):
            out.append(t.removesuffix(" (deleted)"))
    return out


def classify(path):
    """The kind of secret a path is, or None."""
    for kind, (_, rx, _, _) in KINDS.items():
        if rx.search(path):
            return kind
    return None


def held(proc_root, pid):
    """([{kind, label, path}], readable) for one process."""
    paths = open_files(proc_root, pid)
    if paths is None:
        return [], False
    out, seen = [], set()
    for p in paths:
        k = classify(p)
        if k and (k, p) not in seen:
            seen.add((k, p))
            out.append({"kind": k, "label": KINDS[k][0], "path": p})
    order = list(KINDS)
    return sorted(out, key=lambda x: (order.index(x["kind"]), x["path"])), True


def _names(proc):
    exe = (proc.get("exe") or "").removesuffix(" (deleted)")
    names = {os.path.basename(exe), proc.get("comm") or ""}
    cmd = proc.get("cmdline") or []
    for a in cmd[:2]:              # "python3 /usr/bin/electrum", "/opt/Exodus/Exodus"
        names.add(os.path.basename(a))
    return {n for n in names if n}


def expected(proc, kind):
    """True if this process normally holds this kind of secret (its owner, a backup, an editor)."""
    names = _names(proc)
    if names & (KINDS[kind][2] | READERS):
        return True
    if names & EDITORS and kind in ("cloud_creds", "ssh_key", "gpg_key"):
        return True              # you opened ~/.aws/credentials in an editor
    exe = proc.get("exe") or ""
    # a browser's helper processes run from the browser's own folder (/opt/google/chrome/chrome_crashpad_handler)
    if kind.startswith("browser") and re.search(r"/(chrom|brave|vivaldi|opera|firefox|librewolf|waterfox|"
                                                r"floorp|thunderbird|msedge|microsoft)", exe, re.I):
        return True
    return False


def unexpected(proc):
    """The secrets this process holds that it has no business holding."""
    return [s for s in proc.get("secrets") or [] if not expected(proc, s["kind"])]


def attack(secrets):
    out = []
    for s in secrets:
        for t in KINDS[s["kind"]][3]:
            if t not in out:
                out.append(t)
    return out
