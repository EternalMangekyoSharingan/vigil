//! Which distro this is, from `/etc/os-release` (port of `vigil/core/system.py`).
//!
//! Distro differences live behind the [`Family`] value and small functions with a
//! fallback, so the rest of Vigil stays distro-neutral (docs/RUST_REWRITE.md rule 8).

use std::collections::BTreeMap;
use std::path::Path;

pub type OsRelease = BTreeMap<String, String>;

pub const FAMILY_IDS: &[(&str, &[&str])] = &[
    ("arch", &["arch", "manjaro", "endeavouros", "garuda", "artix", "cachyos"]),
    ("fedora", &["fedora", "rhel", "centos", "rocky", "almalinux", "nobara"]),
    ("suse", &["opensuse", "suse", "opensuse-tumbleweed", "opensuse-leap", "sles"]),
    ("debian", &["debian", "ubuntu", "linuxmint", "pop", "elementary", "zorin", "kali", "raspbian"]),
    ("void", &["void"]),
    ("alpine", &["alpine"]),
    ("gentoo", &["gentoo"]),
];

/// Parse os-release text into keys and values (quotes removed).
pub fn parse_os_release(text: &str) -> OsRelease {
    let mut out = OsRelease::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            if !k.starts_with('#') {
                out.insert(k.to_string(), v.trim().trim_matches('"').trim_matches('\'').to_string());
            }
        }
    }
    out
}

/// Read `path`; for the default path fall back to `/usr/lib/os-release`.
pub fn os_release(path: &Path) -> OsRelease {
    let default = path == Path::new("/etc/os-release");
    let candidates: Vec<&Path> = if default { vec![path, Path::new("/usr/lib/os-release")] } else { vec![path] };
    candidates
        .into_iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|t| parse_os_release(&t))
        .unwrap_or_default()
}

/// The distro family ("arch", "fedora", "suse", "debian", ...) or None when unknown.
pub fn family(osr: &OsRelease) -> Option<&'static str> {
    let mut ids = vec![osr.get("ID").map(|s| s.to_lowercase()).unwrap_or_default()];
    ids.extend(osr.get("ID_LIKE").map(|s| s.to_lowercase()).unwrap_or_default().split_whitespace().map(String::from));
    FAMILY_IDS.iter().find(|(_, names)| ids.iter().any(|i| names.contains(&i.as_str()))).map(|(f, _)| *f)
}
