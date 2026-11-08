//! Split a shell command into coloured, explained tokens for the Fix panel, and decide
//! whether Run mode may run it.
//!
//! Port of Vigil 1's `vigil/core/commands.py` (tokens) and the checks in
//! `vigil/core/runner.py` (`argv_for`). Nothing here runs anything: [`tokenize`] only
//! labels words, and [`plan`] only says which argument list *would* be run and why a
//! command is refused. Each token gets a role and a tooltip, so colour is never the only
//! signal.
//!
//! ```text
//! sudo pacman -S syncthing  ->  [admin][pkgmgr:arch][install][package]
//! ```

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub text: String,
    pub role: String,
    pub tip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
}

pub const ADMIN: &[(&str, &str)] = &[
    ("sudo", "Runs the rest as administrator (root). Read the command before you type your password."),
    ("doas", "Runs the rest as administrator (root)."),
    ("pkexec", "Asks for your password, then runs the rest as administrator (root)."),
    ("su", "Switches to another user, normally root."),
    ("sudoedit", "Opens the file in your editor with administrator rights, then saves it as root."),
];

/// command -> (distro family, description)
pub const PKGMGR: &[(&str, &str, &str)] = &[
    ("pacman", "arch", "pacman, Arch Linux's package manager"),
    ("dnf", "fedora", "dnf, Fedora's package manager"),
    ("dnf5", "fedora", "dnf5, Fedora's package manager"),
    ("rpm", "rpm", "rpm, the RPM package database (Fedora, openSUSE)"),
    ("zypper", "suse", "zypper, openSUSE's package manager"),
    ("apt", "debian", "apt, Debian/Ubuntu's package manager"),
    ("apt-get", "debian", "apt-get, Debian/Ubuntu's package manager"),
    ("dpkg", "debian", "dpkg, the Debian package database"),
    ("xbps-install", "void", "xbps-install, Void Linux's installer"),
    ("xbps-remove", "void", "xbps-remove, Void Linux's remover"),
    ("xbps-query", "void", "xbps-query, Void Linux's package database"),
    ("apk", "alpine", "apk, Alpine Linux's package manager"),
    ("emerge", "gentoo", "emerge, Gentoo's package manager"),
    ("equery", "gentoo", "equery, Gentoo's package query tool"),
    ("flatpak", "flatpak", "flatpak, the Flatpak app manager"),
];

/// Words that install or turn something on.
const INSTALL: &[&str] = &["install", "add", "enable", "start", "unmask", "reload", "restart", "-S", "-U", "--now-enable"];
/// Words that remove or turn something off.
const REMOVE: &[&str] = &[
    "remove", "purge", "erase", "del", "autoremove", "disable", "stop", "mask", "-R", "-Rs", "-Rns", "-Rn",
    "--depclean", "--unmerge", "-C", "deny", "reject", "delete", "rm", "drop",
];
const QUERY: &[&str] = &[
    "-Qo", "-Qi", "-Q", "-qf", "-qi", "-o", "--who-owns", "belongs", "info", "status", "show", "list-timers", "query",
    "-S",
];

const FLAG_TIPS: &[(&str, &str)] = &[
    ("--now", "Also start/stop it right away, not only at next boot."),
    ("--user", "Acts on your own user's services, not the system's: no admin rights needed."),
    ("--all", "Include inactive items too."),
    ("--permanent", "Keep the change after a reboot."),
    ("-v", "Verbose: more detail."),
];

const COMMAND_TIPS: &[(&str, &str)] = &[
    ("systemctl", "systemctl, which starts, stops and enables services"),
    ("firewall-cmd", "firewall-cmd, the firewalld firewall's command line"),
    ("ufw", "ufw, the 'uncomplicated firewall'"),
    ("nft", "nft, the nftables firewall"),
    ("nmcli", "nmcli, NetworkManager's command line"),
    ("NetworkManager", "NetworkManager itself"),
    ("rm", "rm deletes a file. It names one exact file here."),
    ("ss", "ss lists network connections"),
    ("timedatectl", "timedatectl shows and sets the system clock"),
    ("chronyc", "chronyc talks to the chrony time service"),
    ("gsettings", "gsettings changes a GNOME setting"),
    ("cat", "cat prints a file"),
    ("ls", "ls lists files"),
    ("journalctl", "journalctl reads the system log"),
];

const SYSTEMCTL_TIPS: &[(&str, &str)] = &[
    ("enable", "Turns it on at every boot."),
    ("start", "Starts it now."),
    ("unmask", "Allows it to start again."),
    ("reload", "Re-reads its configuration."),
    ("restart", "Restarts it."),
    ("disable", "Stops it starting at boot."),
    ("stop", "Stops it now."),
    ("mask", "Blocks it from being started at all."),
    ("status", "Shows its state (read-only)."),
    ("list-timers", "Lists scheduled jobs (read-only)."),
];

/// The legend under every Fix panel: (role, label, description).
pub const LEGEND: &[(&str, &str, &str)] = &[
    ("admin", "Admin / root", "Runs with administrator rights (sudo, doas, pkexec, su)"),
    ("pkgmgr", "Package manager", "Installs or removes software; colour shows the distro family"),
    ("install", "Install / turn on", "Adds a package, or enables or starts something"),
    ("remove", "Remove / turn off", "Removes, disables, stops or blocks something"),
    ("package", "Package or app", "What the command acts on"),
    ("path", "File path", "A file or folder"),
    ("flag", "Option", "Changes how the command behaves; read-only queries too"),
    ("service", "Service manager", "systemctl, which controls services"),
];

fn lookup<'a>(table: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    table.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn pkgmgr(word: &str) -> Option<(&'static str, &'static str)> {
    PKGMGR.iter().find(|(k, _, _)| *k == word).map(|(_, f, d)| (*f, *d))
}

/// `re.findall(r"""'[^']*'|"[^"]*"|\S+""", command)`
pub fn words(command: &str) -> Vec<String> {
    let s: Vec<char> = command.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if (c == '\'' || c == '"') && s[i + 1..].contains(&c) {
            let close = i + 1 + s[i + 1..].iter().position(|&x| x == c).unwrap_or(0);
            out.push(s[i..=close].iter().collect());
            i = close + 1;
        } else if c.is_whitespace() {
            i += 1;
        } else {
            let end = (i..s.len()).find(|&j| s[j].is_whitespace()).unwrap_or(s.len());
            out.push(s[i..end].iter().collect());
            i = end;
        }
    }
    out
}

fn is_path(w: &str) -> bool {
    (w.starts_with('/') || w.starts_with("~/") || w.starts_with("./")) && w.chars().count() > 1
}

/// (role, tip) for a package manager's action word, or None.
fn pkg_action(tool: &str, w: &str) -> Option<(&'static str, String)> {
    let rest = w.get(2..).unwrap_or("");
    match tool {
        "pacman" if w.starts_with("-S") && !rest.contains('s') && !rest.contains('i') => {
            return Some(("install", "-S installs (syncs) the packages named after it.".into()))
        }
        "pacman" if w.starts_with("-R") => {
            return Some(("remove", "-R removes the package; n removes its config files, s unneeded dependencies.".into()))
        }
        "pacman" if w.starts_with("-Q") => {
            return Some(("flag", "-Q queries the installed-package database (read-only); o asks who owns a file.".into()))
        }
        "dpkg" if w == "-S" || w == "--search" => {
            return Some(("flag", "-S searches which package owns a file (read-only).".into()))
        }
        "rpm" if w.starts_with("-q") => {
            return Some(("flag", "-q queries the package database (read-only); f asks who owns a file.".into()))
        }
        "xbps-query" if w == "-o" => return Some(("flag", "-o asks which package owns a file (read-only).".into())),
        "apk" if w == "info" => return Some(("flag", "Queries installed packages (read-only).".into())),
        "equery" if w == "belongs" => return Some(("flag", "Asks which package owns a file (read-only).".into())),
        "emerge" if w == "--depclean" => {
            return Some(("remove", "--depclean removes the package if nothing else needs it.".into()))
        }
        _ => {}
    }
    if ["install", "add"].contains(&w) {
        return Some(("install", format!("{w} installs the packages named after it.")));
    }
    if ["remove", "del", "erase", "purge", "autoremove", "uninstall"].contains(&w) {
        return Some(("remove", format!("{w} removes the packages named after it.")));
    }
    if ["info", "search", "list", "remotes", "query"].contains(&w) {
        return Some(("flag", format!("{w} only reads information.")));
    }
    None
}

/// Every word of one command line, with its role and tooltip.
pub fn tokenize(command: &str) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::new();
    let mut tool: Option<String> = None;
    let mut seen_action = false;
    for w in words(command) {
        let bare = w.trim_matches(|c| c == '\'' || c == '"');
        let t = |role: &str, tip: String| Token { text: w.clone(), role: role.into(), tip, family: None };
        let in_pkg = tool.as_deref().is_some_and(|t| pkgmgr(t).is_some());
        let tok = if tool.is_none() && lookup(ADMIN, &w).is_some() {
            if w == "sudoedit" {
                tool = Some(w.clone());
            }
            t("admin", lookup(ADMIN, &w).unwrap_or_default().into())
        } else if tool.is_none() {
            tool = Some(w.clone());
            if let Some((family, desc)) = pkgmgr(&w) {
                seen_action = w == "xbps-install" || w == "xbps-remove";
                Token { family: Some(family.into()), ..t("pkgmgr", format!("{desc}.")) }
            } else if w == "systemctl" {
                t("service", lookup(COMMAND_TIPS, "systemctl").unwrap_or_default().into())
            } else {
                t("command", lookup(COMMAND_TIPS, &w).map_or_else(|| format!("The program {w}."), String::from))
            }
        } else if is_path(bare) {
            t("path", "A file or folder path.".into())
        } else if let Some((role, tip)) = (in_pkg && !seen_action).then(|| pkg_action(tool.as_deref().unwrap_or(""), &w)).flatten() {
            seen_action = true;
            t(role, tip)
        } else if tool.as_deref() == Some("systemctl")
            && !seen_action
            && !w.starts_with('-')
            && (INSTALL.contains(&w.as_str()) || REMOVE.contains(&w.as_str()) || QUERY.contains(&w.as_str()))
        {
            seen_action = true;
            let role = if INSTALL.contains(&w.as_str()) {
                "install"
            } else if REMOVE.contains(&w.as_str()) {
                "remove"
            } else {
                "flag"
            };
            t(role, lookup(SYSTEMCTL_TIPS, &w).unwrap_or(&w).to_string())
        } else if matches!(tool.as_deref(), Some("ufw" | "firewall-cmd" | "nft" | "timedatectl" | "gsettings"))
            && !w.starts_with('-')
            && (REMOVE.contains(&w.as_str()) || INSTALL.contains(&w.as_str()))
        {
            if REMOVE.contains(&w.as_str()) {
                t("remove", "Blocks or removes something.".into())
            } else {
                t("install", "Adds or turns something on.".into())
            }
        } else if w.starts_with('-') {
            let key = w.split('=').next().unwrap_or("");
            t("flag", lookup(FLAG_TIPS, key).unwrap_or("An option that changes how the command behaves.").into())
        } else if (in_pkg || tool.as_deref() == Some("systemctl")) && seen_action {
            t(
                "package",
                if in_pkg { "The package, app or service this acts on." } else { "The service (or timer) this acts on." }
                    .into(),
            )
        } else {
            t("arg", "An argument for the command.".into())
        };
        out.push(tok);
    }
    if tool.as_deref() == Some("rm") {
        for t in out.iter_mut().filter(|t| t.text == "rm") {
            t.role = "remove".into();
            t.tip = "rm deletes a file. It names one exact file here.".into();
        }
    }
    out
}

// ---- Run mode: what would run, or why not ------------------------------------------------

/// Programs that run the rest of the command as root. Run mode replaces them with
/// polkit, so the system's own dialog takes the password.
pub const RUN_ADMIN: [&str; 3] = ["sudo", "doas", "pkexec"];
/// Interactive editors: copy only.
pub const NOT_RUNNABLE: [&str; 1] = ["sudoedit"];
/// Shell syntax outside quotes: Run mode never uses a shell, so these are refused.
pub const SHELL_SYNTAX: [&str; 10] = ["|", "&&", "||", ";", ">", "<", "`", "$(", "*", "?"];

/// What Run mode would do with a command: the program and its arguments (no shell),
/// and whether it needs admin rights (granted only through polkit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunPlan {
    pub program: String,
    pub args: Vec<String>,
    pub admin: bool,
}

/// The command with quoted parts removed (quoted text is data, not shell syntax).
pub fn unquoted_text(command: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    for ch in command.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None => out.push(ch),
        }
    }
    out
}

/// Python's `shlex.split` (POSIX mode, no comments): quotes group words, a backslash
/// escapes the next character outside single quotes.
pub fn shell_words(command: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(x) => cur.push(x),
                        None => return Err("No closing quotation".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(x @ ('"' | '\\' | '$' | '`' | '\n')) => cur.push(x),
                            Some(x) => {
                                cur.push('\\');
                                cur.push(x);
                            }
                            None => return Err("No closing quotation".into()),
                        },
                        Some(x) => cur.push(x),
                        None => return Err("No closing quotation".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some(x) => cur.push(x),
                    None => return Err("No escaped character".into()),
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    Ok(out)
}

/// The argument list Run mode would use for `command`, or why it is refused.
///
/// The program is returned as written (not resolved on `PATH`): the daemon resolves it
/// and replaces an admin prefix with polkit. `home` expands a leading `~/`.
pub fn plan(command: &str, home: &str) -> Result<RunPlan, String> {
    let words = shell_words(command).map_err(|e| format!("cannot parse the command: {e}"))?;
    if words.is_empty() {
        return Err("empty command".into());
    }
    let unquoted = unquoted_text(command);
    if SHELL_SYNTAX.iter().any(|s| unquoted.contains(s)) {
        return Err("contains shell syntax (pipes, chains, redirects or wildcards); copy it instead".into());
    }
    if NOT_RUNNABLE.contains(&words[0].as_str()) {
        return Err(format!("{} opens an editor; copy it and run it in a terminal", words[0]));
    }
    let admin = RUN_ADMIN.contains(&words[0].as_str());
    let words = if admin { &words[1..] } else { &words[..] };
    let Some((program, rest)) = words.split_first() else { return Err("nothing to run".into()) };
    let args = rest
        .iter()
        .map(|w| w.strip_prefix("~/").map_or_else(|| w.clone(), |r| format!("{home}/{r}")))
        .collect();
    Ok(RunPlan { program: program.clone(), args, admin })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(c: &str) -> Vec<String> {
        tokenize(c).into_iter().map(|t| t.role).collect()
    }

    #[test]
    fn pacman_install() {
        assert_eq!(roles("sudo pacman -S syncthing"), ["admin", "pkgmgr", "install", "package"]);
        assert_eq!(tokenize("sudo pacman -S syncthing")[1].family.as_deref(), Some("arch"));
    }

    #[test]
    fn run_plans() {
        let p = plan("sudo systemctl disable --now foo.service", "/home/u").unwrap();
        assert!(p.admin);
        assert_eq!(p.program, "systemctl");
        assert_eq!(plan("rm ~/.config/x", "/home/u").unwrap().args, ["/home/u/.config/x"]);
        assert!(plan("curl x | sh", "/h").unwrap_err().contains("shell syntax"));
        assert!(plan("sudoedit /etc/sudoers", "/h").unwrap_err().contains("editor"));
        assert!(plan("sudo", "/h").unwrap_err().contains("nothing to run"));
        assert!(plan("echo 'unclosed", "/h").unwrap_err().contains("cannot parse"));
        // Quoted text is data: a pipe inside quotes is not shell syntax.
        assert_eq!(plan("grep 'a|b' /etc/x", "/h").unwrap().args, ["a|b", "/etc/x"]);
    }
}
