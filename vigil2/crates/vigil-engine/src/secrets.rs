//! Which running programs have your secrets open: SSH keys, browser passwords and cookies,
//! password databases, keyrings, chat tokens, wallets, cloud credentials (Vigil 1's
//! tasks/secrets.py, held to it by tests/golden/tasks.json).
//!
//! Vigil 1 matches paths with regular expressions; the `regex` crate is not on the allowed
//! list yet (DECISIONS D-003), so each pattern is a small hand-written matcher with the
//! original expression next to it.

use crate::tasks::ProcFacts;

pub struct Kind {
    pub id: &'static str,
    pub label: &'static str,
    /// Programs that normally hold this kind of secret.
    pub owners: &'static [&'static str],
    pub attack: &'static [&'static str],
    matches: fn(&str) -> bool,
}

const BROWSERS_CHROMIUM: &[&str] = &[
    "chrome",
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave",
    "brave-browser",
    "msedge",
    "microsoft-edge",
    "opera",
    "vivaldi",
    "vivaldi-bin",
    "thorium",
    "yandex_browser",
    "electron",
    "chrome_crashpad_handler",
    "code",
    "codium",
    "slack",
    "signal-desktop",
    "spotify",
    "obsidian",
    "teams-for-linux",
];
const BROWSERS_GECKO: &[&str] = &[
    "firefox",
    "firefox-bin",
    "firefox-esr",
    "librewolf",
    "waterfox",
    "floorp",
    "zen",
    "zen-bin",
    "thunderbird",
    "thunderbird-bin",
    "betterbird",
    "seamonkey",
    "icecat",
    "mullvadbrowser",
];
const SSH: &[&str] = &[
    "ssh",
    "ssh-agent",
    "ssh-add",
    "ssh-keygen",
    "sshd",
    "gpg-agent",
    "gnome-keyring-daemon",
    "seahorse",
    "keepassxc",
    "ksshaskpass",
    "kwalletd5",
    "kwalletd6",
    "scp",
    "sftp",
    "git",
    "mosh-client",
    "autossh",
];
const GPG: &[&str] = &["gpg", "gpg2", "gpg-agent", "gpgsm", "scdaemon", "kleopatra", "seahorse", "keyboxd"];
const VAULTS: &[&str] =
    &["keepassxc", "keepass", "keepass2", "keeweb", "kpcli", "mono", "secrets", "gnome-passwords", "passwordsafe"];
const KEYRINGS: &[&str] =
    &["gnome-keyring-daemon", "kwalletd5", "kwalletd6", "seahorse", "kwalletmanager5", "kwalletmanager", "secret-tool"];
const CHAT: &[&str] = &[
    "discord",
    "Discord",
    "discord-canary",
    "discordcanary",
    "discord-ptb",
    "vesktop",
    "webcord",
    "electron",
    "armcord",
    "legcord",
    "telegram-desktop",
    "Telegram",
    "element-desktop",
];
const WALLETS: &[&str] = &[
    "bitcoind",
    "bitcoin-qt",
    "electrum",
    "exodus",
    "Exodus",
    "monero-wallet-gui",
    "monerod",
    "geth",
    "ledger-live",
    "ledger-live-desktop",
    "sparrow",
    "wasabi",
    "feather",
];
const CLOUD: &[&str] = &[
    "aws",
    "kubectl",
    "k9s",
    "helm",
    "docker",
    "dockerd",
    "podman",
    "gcloud",
    "az",
    "terraform",
    "lens",
    "openlens",
    "git",
    "git-credential-libsecret",
    "git-credential-store",
    "psql",
    "curl",
];
/// Programs that read everything by design: backups, sync, indexers.
const READERS: &[&str] = &[
    "borg",
    "restic",
    "rsync",
    "rclone",
    "duplicity",
    "deja-dup",
    "kopia",
    "tar",
    "syncthing",
    "dropbox",
    "nextcloud",
    "owncloud",
    "megasync",
    "baloo_file",
    "baloo_file_extractor",
    "tracker-miner-fs-3",
    "tracker-extract-3",
    "localsearch-3",
    "updatedb",
    "plocate",
    "mlocate",
    "clamscan",
    "clamd",
    "rkhunter",
    "timeshift",
    "snapper",
    "btrbk",
    "pika-backup",
    "vorta",
    "back-in-time",
    "backintime",
];
const EDITORS: &[&str] = &[
    "vim",
    "nvim",
    "vi",
    "nano",
    "emacs",
    "micro",
    "helix",
    "hx",
    "kate",
    "gedit",
    "gnome-text-editor",
    "mousepad",
    "code",
    "codium",
    "zed",
    "subl",
    "less",
    "more",
    "bat",
    "cat",
    "view",
];

/// (directory, file name) of a path, split at the last '/' (None without a '/').
fn split(path: &str) -> Option<(&str, &str)> {
    path.rsplit_once('/')
}

/// `/\.ssh/(id_[a-z0-9_-]+|[^/]+_key|[^/]+\.pem)$`
fn ssh_key(p: &str) -> bool {
    let Some((dir, file)) = split(p) else { return false };
    if !dir.ends_with("/.ssh") {
        return false;
    }
    let id = file.strip_prefix("id_").is_some_and(|r| {
        !r.is_empty() && r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    });
    id || (file.len() > 4 && file.ends_with("_key")) || (file.len() > 4 && file.ends_with(".pem"))
}

/// `/\.gnupg/(private-keys-v1\.d/|secring\.gpg$)`
fn gpg_key(p: &str) -> bool {
    p.contains("/.gnupg/private-keys-v1.d/") || p.ends_with("/.gnupg/secring.gpg")
}

fn file_in(p: &str, names: &[&str]) -> bool {
    split(p).is_some_and(|(_, f)| names.contains(&f))
}

/// `/(Login Data|Login Data For Account|logins\.json|key4\.db|key3\.db|signons\.sqlite)$`
fn browser_passwords(p: &str) -> bool {
    file_in(p, &["Login Data", "Login Data For Account", "logins.json", "key4.db", "key3.db", "signons.sqlite"])
}

/// `/(Cookies|cookies\.sqlite|Network/Cookies)$`
fn browser_cookies(p: &str) -> bool {
    file_in(p, &["Cookies", "cookies.sqlite"])
}

/// `/(Local State|Web Data)$`
fn browser_keys(p: &str) -> bool {
    file_in(p, &["Local State", "Web Data"])
}

/// `\.(kdbx|kdb|psafe3|1pif)$`
fn password_db(p: &str) -> bool {
    [".kdbx", ".kdb", ".psafe3", ".1pif"].iter().any(|e| p.ends_with(e))
}

/// `/(\.local/share/keyrings/[^/]+\.keyring|\.local/share/kwalletd/[^/]+\.kwl)$`
fn keyring(p: &str) -> bool {
    let Some((dir, file)) = split(p) else { return false };
    (dir.ends_with("/.local/share/keyrings") && file.len() > ".keyring".len() && file.ends_with(".keyring"))
        || (dir.ends_with("/.local/share/kwalletd") && file.len() > ".kwl".len() && file.ends_with(".kwl"))
}

/// `/(discord[a-z]*|Discord|vesktop|WebCord|armcord|legcord)/Local Storage/leveldb/`
fn chat_token(p: &str) -> bool {
    let marker = "/Local Storage/leveldb/";
    let mut from = 0;
    while let Some(i) = p[from..].find(marker) {
        let at = from + i;
        if let Some(slash) = p[..at].rfind('/') {
            let comp = &p[slash + 1..at];
            let discord = comp.strip_prefix("discord").is_some_and(|r| r.chars().all(|c| c.is_ascii_lowercase()));
            if discord || ["Discord", "vesktop", "WebCord", "armcord", "legcord"].contains(&comp) {
                return true;
            }
        }
        from = at + 1;
    }
    false
}

/// `/(\.bitcoin/(wallets/.*|wallet\.dat)|\.electrum/wallets/|\.config/Exodus/exodus\.wallet/|
/// \.ethereum/keystore/|\.monero/|Ledger Live/|\.sparrow/wallets/)`
fn wallet(p: &str) -> bool {
    [
        "/.bitcoin/wallets/",
        "/.bitcoin/wallet.dat",
        "/.electrum/wallets/",
        "/.config/Exodus/exodus.wallet/",
        "/.ethereum/keystore/",
        "/.monero/",
        "/Ledger Live/",
        "/.sparrow/wallets/",
    ]
    .iter()
    .any(|m| p.contains(m))
}

/// `/(\.aws/credentials|\.kube/config|...|\.config/gh/hosts\.yml)$`
fn cloud_creds(p: &str) -> bool {
    [
        "/.aws/credentials",
        "/.kube/config",
        "/.docker/config.json",
        "/.netrc",
        "/.git-credentials",
        "/.pgpass",
        "/.config/gcloud/credentials.db",
        "/.config/gcloud/access_tokens.db",
        "/.config/gcloud/application_default_credentials.json",
        "/.azure/msal_token_cache.json",
        "/.azure/accessTokens.json",
        "/.config/gh/hosts.yml",
    ]
    .iter()
    .any(|m| p.ends_with(m))
}

const BROWSERS: &[&str] = &[]; // the union is checked by `owners_of`

/// In Vigil 1's order: the first kind that matches wins.
pub static KINDS: [Kind; 10] = [
    Kind { id: "ssh_key", label: "an SSH private key", owners: SSH, attack: &["T1552.004"], matches: ssh_key },
    Kind { id: "gpg_key", label: "GnuPG private keys", owners: GPG, attack: &["T1552.004"], matches: gpg_key },
    Kind {
        id: "browser_passwords",
        label: "saved browser passwords",
        owners: BROWSERS,
        attack: &["T1555.003"],
        matches: browser_passwords,
    },
    Kind {
        id: "browser_cookies",
        label: "browser cookies (logged-in sessions)",
        owners: BROWSERS,
        attack: &["T1539"],
        matches: browser_cookies,
    },
    Kind {
        id: "browser_keys",
        label: "the browser's encryption key",
        owners: BROWSERS_CHROMIUM,
        attack: &["T1555.003"],
        matches: browser_keys,
    },
    Kind {
        id: "password_db",
        label: "a password database",
        owners: VAULTS,
        attack: &["T1555.005"],
        matches: password_db,
    },
    Kind { id: "keyring", label: "the desktop keyring", owners: KEYRINGS, attack: &["T1555"], matches: keyring },
    Kind { id: "chat_token", label: "a chat app's login token", owners: CHAT, attack: &["T1528"], matches: chat_token },
    Kind { id: "wallet", label: "a cryptocurrency wallet", owners: WALLETS, attack: &["T1005"], matches: wallet },
    Kind {
        id: "cloud_creds",
        label: "cloud or developer credentials",
        owners: CLOUD,
        attack: &["T1552.001"],
        matches: cloud_creds,
    },
];

pub fn kind(id: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|k| k.id == id)
}

/// The kind of secret a path is, or None.
pub fn classify(path: &str) -> Option<&'static str> {
    KINDS.iter().find(|k| (k.matches)(path)).map(|k| k.id)
}

fn owners_of(k: &Kind, name: &str) -> bool {
    match k.id {
        "browser_passwords" | "browser_cookies" => BROWSERS_CHROMIUM.contains(&name) || BROWSERS_GECKO.contains(&name),
        _ => k.owners.contains(&name),
    }
}

/// os.path.basename
pub fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn names(p: &ProcFacts) -> Vec<String> {
    let exe = p.exe.as_deref().unwrap_or("");
    let exe = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    let mut v = vec![basename(exe).to_string(), p.comm.clone()];
    v.extend(p.cmdline.iter().take(2).map(|a| basename(a).to_string()));
    v.retain(|n| !n.is_empty());
    v
}

/// True if this process normally holds this kind of secret (its owner, a backup, an editor).
pub fn expected(p: &ProcFacts, kind_id: &str) -> bool {
    let Some(k) = kind(kind_id) else { return false };
    let names = names(p);
    if names.iter().any(|n| owners_of(k, n) || READERS.contains(&n.as_str())) {
        return true;
    }
    if names.iter().any(|n| EDITORS.contains(&n.as_str())) && matches!(kind_id, "cloud_creds" | "ssh_key" | "gpg_key") {
        return true;
    }
    // A browser's helpers run from the browser's own folder (chrome_crashpad_handler).
    let exe = p.exe.as_deref().unwrap_or("").to_lowercase();
    kind_id.starts_with("browser")
        && [
            "/chrom",
            "/brave",
            "/vivaldi",
            "/opera",
            "/firefox",
            "/librewolf",
            "/waterfox",
            "/floorp",
            "/thunderbird",
            "/msedge",
            "/microsoft",
        ]
        .iter()
        .any(|m| exe.contains(m))
}

/// The secrets this process holds that it has no business holding.
pub fn unexpected(p: &ProcFacts) -> Vec<&crate::tasks::Secret> {
    p.secrets.iter().filter(|s| !expected(p, &s.kind)).collect()
}

/// ATT&CK techniques for these secrets, without repeats.
pub fn attack(secrets: &[&crate::tasks::Secret]) -> Vec<&'static str> {
    let mut out = vec![];
    for s in secrets {
        for t in kind(&s.kind).map_or(&[][..], |k| k.attack) {
            if !out.contains(t) {
                out.push(*t);
            }
        }
    }
    out
}

/// Secrets among a process's open files (paths from readlink on /proc/<pid>/fd).
pub fn held(paths: &[String]) -> Vec<crate::tasks::Secret> {
    let mut out: Vec<crate::tasks::Secret> = vec![];
    for p in paths {
        if let Some(k) = classify(p) {
            if !out.iter().any(|s| s.kind == k && &s.path == p) {
                out.push(crate::tasks::Secret {
                    kind: k.to_string(),
                    label: kind(k).map_or("", |x| x.label).to_string(),
                    path: p.clone(),
                });
            }
        }
    }
    let order = |k: &str| KINDS.iter().position(|x| x.id == k).unwrap_or(99);
    out.sort_by(|a, b| order(&a.kind).cmp(&order(&b.kind)).then(a.path.cmp(&b.path)));
    out
}
