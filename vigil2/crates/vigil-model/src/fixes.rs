//! Check / Fix / Undo options: commands for the user to read, copy and (in Run mode)
//! run after confirming the exact text.
//!
//! Port of Vigil 1's `vigil/core/fixes.py`. This module only builds text and has no way
//! to start a process. Every area builds its Fix panel here, so commands look and behave
//! the same everywhere.
//!
//! Rules every command follows: one action per command, no `curl | sh`, no `&&` chains,
//! no wildcards in rm, and every fix has an undo.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::commands::{self, Token};
use crate::distro::{self, OsRelease};

/// Package manager templates per distro family.
pub struct PkgTemplates {
    pub family: &'static str,
    pub name: &'static str,
    pub install: &'static str,
    pub remove: &'static str,
    pub owner: &'static str,
}

pub const PKG: &[PkgTemplates] = &[
    PkgTemplates {
        family: "arch",
        name: "Arch Linux",
        install: "sudo pacman -S {pkg}",
        remove: "sudo pacman -Rns {pkg}",
        owner: "pacman -Qo {path}",
    },
    PkgTemplates {
        family: "fedora",
        name: "Fedora",
        install: "sudo dnf install {pkg}",
        remove: "sudo dnf remove {pkg}",
        owner: "rpm -qf {path}",
    },
    PkgTemplates {
        family: "suse",
        name: "openSUSE",
        install: "sudo zypper install {pkg}",
        remove: "sudo zypper remove {pkg}",
        owner: "rpm -qf {path}",
    },
    PkgTemplates {
        family: "debian",
        name: "Debian / Ubuntu",
        install: "sudo apt install {pkg}",
        remove: "sudo apt remove {pkg}",
        owner: "dpkg -S {path}",
    },
    PkgTemplates {
        family: "void",
        name: "Void Linux",
        install: "sudo xbps-install {pkg}",
        remove: "sudo xbps-remove -R {pkg}",
        owner: "xbps-query -o {path}",
    },
    PkgTemplates {
        family: "alpine",
        name: "Alpine Linux",
        install: "doas apk add {pkg}",
        remove: "doas apk del {pkg}",
        owner: "apk info --who-owns {path}",
    },
    PkgTemplates {
        family: "gentoo",
        name: "Gentoo",
        install: "sudo emerge --ask {pkg}",
        remove: "sudo emerge --ask --depclean {pkg}",
        owner: "equery belongs {path}",
    },
];

pub fn templates(family: &str) -> Option<&'static PkgTemplates> {
    PKG.iter().find(|t| t.family == family)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Safe,
    Settings,
    Admin,
    Deletes,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::Safe => "Safe (read-only)",
            Risk::Settings => "Changes settings",
            Risk::Admin => "Admin needed",
            Risk::Deletes => "Deletes files (rebuilt as needed)",
        }
    }
}

/// One copyable command with its colour-coded tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub text: String,
    pub tokens: Vec<Token>,
}

pub fn command(text: &str) -> Command {
    Command { text: text.to_string(), tokens: commands::tokenize(text) }
}

fn is_empty_vec<T>(v: &[T]) -> bool {
    v.is_empty()
}

/// One Check or Fix option.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixOption {
    pub title: String,
    pub what: String,
    pub risk: Risk,
    pub risk_label: String,
    #[serde(default)]
    pub commands: Vec<Command>,
    #[serde(default)]
    pub undo: Vec<Command>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lose: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    pub steps: Vec<String>,
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    pub undo_steps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Keys this version does not know (kept so imported findings round-trip).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Build an option. `commands` and `undo` are plain command strings.
pub fn option(title: &str, what: &str, risk: Risk, commands: &[&str], undo: &[&str]) -> FixOption {
    FixOption {
        title: title.into(),
        what: what.into(),
        risk,
        risk_label: risk.label().into(),
        commands: commands.iter().map(|c| command(c)).collect(),
        undo: undo.iter().map(|c| command(c)).collect(),
        lose: None,
        steps: vec![],
        undo_steps: vec![],
        file: None,
        extra: Map::new(),
    }
}

impl FixOption {
    pub fn with_steps(mut self, steps: &[&str], undo_steps: &[&str]) -> Self {
        self.steps = steps.iter().map(|s| s.to_string()).collect();
        self.undo_steps = undo_steps.iter().map(|s| s.to_string()).collect();
        self
    }
    pub fn with_lose(mut self, lose: &str) -> Self {
        self.lose = Some(lose.into()).filter(|s: &String| !s.is_empty());
        self
    }
    pub fn with_file(mut self, file: &str) -> Self {
        self.file = Some(file.into()).filter(|s: &String| !s.is_empty());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UndoEntry {
    pub title: String,
    #[serde(rename = "for")]
    pub for_: String,
    pub commands: Vec<Command>,
    pub steps: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistroInfo {
    pub id: Option<String>,
    pub name: Option<String>,
    pub family: Option<String>,
    pub known: bool,
}

pub fn distro_info(osr: &OsRelease) -> DistroInfo {
    let fam = distro::family(osr);
    DistroInfo {
        id: osr.get("ID").cloned(),
        name: osr.get("PRETTY_NAME").filter(|s| !s.is_empty()).or_else(|| osr.get("NAME")).cloned(),
        family: fam.map(String::from),
        known: fam.is_some(),
    }
}

/// The Fix panel every area shows: distro, Check options, Fix options and their Undo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixPanel {
    pub distro: DistroInfo,
    pub firewall: Option<String>,
    #[serde(default)]
    pub check: Vec<FixOption>,
    #[serde(default)]
    pub fix: Vec<FixOption>,
    #[serde(default)]
    pub undo: Vec<UndoEntry>,
    #[serde(default)]
    pub legend: Vec<(String, String, String)>,
    pub note: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub fn panel(osr: &OsRelease, check: Vec<FixOption>, fix: Vec<FixOption>, firewall: Option<&str>) -> FixPanel {
    let fam = distro::family(osr);
    let undo = fix
        .iter()
        .filter(|o| !o.undo.is_empty() || !o.undo_steps.is_empty())
        .map(|o| UndoEntry {
            title: format!("Undo: {}", o.title),
            for_: o.title.clone(),
            commands: o.undo.clone(),
            steps: (!o.undo_steps.is_empty()).then(|| o.undo_steps.clone()),
        })
        .collect();
    FixPanel {
        distro: distro_info(osr),
        firewall: firewall.map(String::from),
        check,
        fix,
        undo,
        legend: commands::LEGEND.iter().map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string())).collect(),
        note: fam.is_none().then(|| {
            "Unknown distro: only generic, read-only checks are shown. \
             Vigil read /etc/os-release and did not recognise ID or ID_LIKE."
                .to_string()
        }),
        extra: Map::new(),
    }
}

/// "Which package installed this file?" for the distro in use (read-only).
pub fn owner_check(path: &str, family: Option<&str>) -> FixOption {
    match family.and_then(templates) {
        Some(t) => option(
            "Which package installed this file?",
            &format!(
                "Asks {}'s package database who owns {path}. \
                 If nothing owns it, it was installed by hand or by something else.",
                t.name
            ),
            Risk::Safe,
            &[&t.owner.replace("{path}", path)],
            &[],
        ),
        None => option(
            "Which package installed this file?",
            &format!(
                "Vigil could not tell your distro from /etc/os-release, so it cannot show the \
                 right command. Ask your package manager which package owns {path}."
            ),
            Risk::Safe,
            &[],
            &[],
        ),
    }
}

impl FixPanel {
    /// Every command text in the panel (Check, Fix and Undo): what Run may run for this
    /// finding. Port of `runner.commands_in`.
    pub fn command_texts(&self) -> std::collections::BTreeSet<String> {
        let opts = self.check.iter().chain(&self.fix);
        let mut out: std::collections::BTreeSet<String> =
            opts.flat_map(|o| o.commands.iter().chain(&o.undo)).map(|c| c.text.clone()).collect();
        out.extend(self.undo.iter().flat_map(|u| &u.commands).map(|c| c.text.clone()));
        out.retain(|t| !t.is_empty());
        out
    }
}
