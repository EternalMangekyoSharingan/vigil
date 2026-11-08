//! `cargo run -p xtask -- <task>`
//!
//! - `dist [--root DIR] [--no-build]`: stage the install tree every package uses
//!   (`usr/bin/vigil`, `usr/lib/vigil/vigild`, units, D-Bus and polkit files ...).
//! - `check-deps`: every direct dependency of every crate is on the allowlist in
//!   docs/RUST_REWRITE.md section 9. Anything else needs the owner's yes first.
//! - `check-packaging`: the packaging files agree with each other and with the code,
//!   and pass the distro validators that are installed.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// docs/RUST_REWRITE.md section 9, plus the toolkit chosen by the spike.
const ALLOWED: &[&str] = &[
    "aya",
    "aya-ebpf",
    "aya-log",
    "tokio",
    "zbus",
    "serde",
    "serde_json",
    "toml",
    "rusqlite",
    "yara-x",
    "nix",
    "procfs",
    "neli",
    "nftables",
    "hickory-proto",
    "goblin",
    "zip",
    "tar",
    "flate2",
    "xz2",
    "zstd",
    "sha2",
    "blake3",
    "minisign-verify",
    "time",
    "thiserror",
    "anyhow",
    "tracing",
    "clap",
    "ratatui",
    "notify-rust",
    "ksni",
    "ureq",
    "reqwest",
    "insta",
    "proptest",
    "criterion",
    // The UI toolkit and its component crate (docs/DECISIONS.md D-002).
    "gpui",
    "gpui_platform",
    "gpui-pre",
    "gpui-pre-platform",
    "gpui-component",
];
const ALLOWED_PREFIX: &[&str] = &["netlink-packet-", "vigil-"];

/// (source in packaging/, destination in the install tree, mode)
const FILES: &[(&str, &str, u32)] = &[
    ("systemd/vigild.service", "usr/lib/systemd/system/vigild.service", 0o644),
    ("systemd/vigil-notify.service", "usr/lib/systemd/user/vigil-notify.service", 0o644),
    ("dbus/org.vigil.Daemon.conf", "usr/share/dbus-1/system.d/org.vigil.Daemon.conf", 0o644),
    ("dbus/org.vigil.Daemon.service", "usr/share/dbus-1/system-services/org.vigil.Daemon.service", 0o644),
    ("polkit/org.vigil.policy", "usr/share/polkit-1/actions/org.vigil.policy", 0o644),
    ("sysusers/vigil.conf", "usr/lib/sysusers.d/vigil.conf", 0o644),
    ("desktop/org.vigil.Vigil.desktop", "usr/share/applications/org.vigil.Vigil.desktop", 0o644),
    ("metainfo/org.vigil.Vigil.metainfo.xml", "usr/share/metainfo/org.vigil.Vigil.metainfo.xml", 0o644),
    ("icons/org.vigil.Vigil.svg", "usr/share/icons/hicolor/scalable/apps/org.vigil.Vigil.svg", 0o644),
];
/// (binary in target/release, destination)
const BINS: &[(&str, &str)] =
    &[("vigild", "usr/lib/vigil/vigild"), ("vigil-cli", "usr/bin/vigil-cli"), ("vigil", "usr/bin/vigil")];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("workspace").to_path_buf()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("dist") => dist(&args[1..]),
        Some("check-deps") => check_deps(),
        Some("check-packaging") => check_packaging(),
        _ => Err("usage: cargo run -p xtask -- dist [--root DIR] [--no-build] | check-deps | check-packaging".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dist(args: &[String]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut stage = root().join("target/dist/root");
    let mut build = true;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--root" => stage = PathBuf::from(it.next().ok_or("--root needs a directory")?),
            "--no-build" => build = false,
            other => return Err(format!("unknown option {other}")),
        }
    }
    if build {
        let ok = Command::new(env!("CARGO"))
            .args(["build", "--release", "--workspace"])
            .current_dir(root())
            .status()
            .map_err(|e| e.to_string())?;
        if !ok.success() {
            return Err("cargo build failed".into());
        }
    }
    let copy = |src: &Path, rel: &str, mode: u32| -> Result<(), String> {
        let dst = stage.join(rel);
        std::fs::create_dir_all(dst.parent().expect("parent")).map_err(|e| e.to_string())?;
        std::fs::copy(src, &dst).map_err(|e| format!("{}: {e}", src.display()))?;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
    };
    for (src, dst, mode) in FILES {
        copy(&root().join("packaging").join(src), dst, *mode)?;
    }
    for (bin, dst) in BINS {
        let src = root().join("target/release").join(bin);
        if src.exists() {
            copy(&src, dst, 0o755)?;
        } else {
            eprintln!("xtask: {bin} was not built; skipped (the app needs `cargo build --release -p vigil-ui`)");
        }
    }
    let license = root().parent().map(|p| p.join("LICENSE")).filter(|p| p.exists());
    if let Some(l) = license {
        copy(&l, "usr/share/licenses/vigil/LICENSE", 0o644)?;
    }
    println!("staged {}", stage.display());
    Ok(())
}

fn deps_of(manifest: &Path) -> Result<Vec<(String, String)>, String> {
    let text = std::fs::read_to_string(manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let doc: toml::Table = text.parse().map_err(|e| format!("{}: {e}", manifest.display()))?;
    let mut out = vec![];
    let mut tables: Vec<(&str, &toml::Value)> = vec![];
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = doc.get(key) {
            tables.push((key, t));
        }
        if let Some(t) = doc.get("workspace").and_then(|w| w.get(key)) {
            tables.push((key, t));
        }
    }
    if let Some(targets) = doc.get("target").and_then(|t| t.as_table()) {
        for t in targets.values() {
            for key in ["dependencies", "dev-dependencies"] {
                if let Some(d) = t.get(key) {
                    tables.push((key, d));
                }
            }
        }
    }
    for (kind, t) in tables {
        for (name, spec) in t.as_table().into_iter().flatten() {
            // `foo = { package = "bar" }` depends on bar.
            let real = spec.get("package").and_then(|p| p.as_str()).unwrap_or(name);
            out.push((kind.to_string(), real.to_string()));
        }
    }
    Ok(out)
}

fn check_deps() -> Result<(), String> {
    let mut manifests = vec![root().join("Cargo.toml"), root().join("xtask/Cargo.toml")];
    for e in std::fs::read_dir(root().join("crates")).map_err(|e| e.to_string())? {
        let p = e.map_err(|e| e.to_string())?.path().join("Cargo.toml");
        if p.exists() {
            manifests.push(p);
        }
    }
    let mut bad = vec![];
    for m in &manifests {
        for (kind, name) in deps_of(m)? {
            if !ALLOWED.contains(&name.as_str()) && !ALLOWED_PREFIX.iter().any(|p| name.starts_with(p)) {
                bad.push(format!("{}: {kind} {name}", m.strip_prefix(root()).unwrap_or(m).display()));
            }
        }
    }
    if bad.is_empty() {
        println!("check-deps: {} manifests, every direct dependency is on the allowlist", manifests.len());
        Ok(())
    } else {
        Err(format!(
            "not on the allowlist (docs/RUST_REWRITE.md section 9; ask the owner first):\n  {}",
            bad.join("\n  ")
        ))
    }
}

fn check_packaging() -> Result<(), String> {
    let p = root().join("packaging");
    let read = |rel: &str| std::fs::read_to_string(p.join(rel)).map_err(|e| format!("{rel}: {e}"));
    let mut problems = vec![];
    // The unit keeps its hardening.
    let unit = read("systemd/vigild.service")?;
    for key in [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "CapabilityBoundingSet=",
        "SystemCallFilter=",
        "MemoryMax=",
        "WatchdogSec=",
        "Restart=on-failure",
        "User=vigil",
        "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "IPAddressDeny=any",
    ] {
        if !unit.contains(key) {
            problems.push(format!("vigild.service lost {key}"));
        }
    }
    for forbidden in ["ProtectProc=", "ProcSubset=", "AF_INET"] {
        if unit.lines().any(|l| !l.trim_start().starts_with('#') && l.contains(forbidden)) {
            problems.push(format!("vigild.service must not use {forbidden}"));
        }
    }
    // Names agree across files and code.
    let bus = "org.vigil.Daemon";
    for rel in ["dbus/org.vigil.Daemon.conf", "dbus/org.vigil.Daemon.service"] {
        if !read(rel)?.contains(bus) {
            problems.push(format!("{rel} does not name {bus}"));
        }
    }
    let policy = read("polkit/org.vigil.policy")?;
    let code = std::fs::read_to_string(root().join("crates/vigild/src/auth.rs")).unwrap_or_default();
    for action in
        code.match_indices("\"org.vigil.").map(|(i, _)| &code[i + 1..]).map(|s| s.split('"').next().unwrap_or(""))
    {
        if action.starts_with("org.vigil.") && action != bus && !policy.contains(&format!("id=\"{action}\"")) {
            problems.push(format!("vigild uses polkit action {action}, which org.vigil.policy does not declare"));
        }
    }
    for (src, _, _) in FILES {
        if !p.join(src).exists() {
            problems.push(format!("missing packaging/{src}"));
        }
    }
    // The distro validators, where installed.
    let tools: &[(&str, &[&str])] = &[
        ("desktop-file-validate", &["desktop/org.vigil.Vigil.desktop"]),
        ("appstreamcli", &["validate", "--no-net", "metainfo/org.vigil.Vigil.metainfo.xml"]),
        ("xmllint", &["--noout", "dbus/org.vigil.Daemon.conf", "polkit/org.vigil.policy", "icons/org.vigil.Vigil.svg"]),
    ];
    for (tool, args) in tools {
        match Command::new(tool).args(*args).current_dir(&p).output() {
            Ok(o) if o.status.success() => println!("check-packaging: {tool} ok"),
            Ok(o) => problems.push(format!(
                "{tool}: {}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )),
            Err(_) => println!("check-packaging: {tool} not installed, skipped"),
        }
    }
    if problems.is_empty() {
        println!("check-packaging: ok");
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}
