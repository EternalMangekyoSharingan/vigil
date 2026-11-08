//! vigil-cli: Vigil in a terminal, through the same daemon and API as the app.
//!
//! ```text
//! vigil-cli status                 what the daemon sees, and how
//! vigil-cli processes [-f TEXT]    every process
//! vigil-cli connections [--all]    who is talking to whom, and which program
//! vigil-cli at -2h                 the time machine: what was talking two hours ago
//! vigil-cli events [--since -1d]   Vigil's own log (first sightings, runs, settings)
//! vigil-cli doctor                 is everything in place? prints fixes
//! ```
//!
//! `--json` prints the daemon's answer as it came. `--bus session` talks to a
//! development daemon (`vigild --bus session`).

use clap::{Parser, Subcommand};
use serde_json::Value;
use std::process::ExitCode;
use vigil_model::api::{BUS_NAME, IFACE_DAEMON, IFACE_EVENTS, IFACE_NETWORK, IFACE_PROCESSES, OBJECT_PATH};
use vigil_model::finding::now;
use vigil_model::host::{DaemonStatus, NetSnapshot, ProcessList};
use vigil_model::wording;
use vigil_store::{Event, StoredConnection};

#[derive(Parser)]
#[command(name = "vigil-cli", version, about = "Vigil in a terminal")]
struct Cli {
    /// "system" (the installed daemon), "session" (a development daemon) or "address=...".
    #[arg(long, global = true, default_value = "system")]
    bus: String,
    /// Print the daemon's JSON instead of a table.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// What the daemon sees and how: sources, store, its own usage.
    Status,
    /// Every process at the daemon's last look.
    Processes {
        /// Only rows containing this text (name, user, command line).
        #[arg(short, long)]
        filter: Option<String>,
    },
    /// Sockets and the programs holding them.
    Connections {
        /// Include listening sockets and loopback traffic.
        #[arg(long)]
        all: bool,
    },
    /// The time machine: connections open at a moment ("-2h", "-30m", or seconds since the epoch).
    At {
        #[arg(allow_hyphen_values = true)]
        when: String,
    },
    /// Vigil's own event log.
    Events {
        #[arg(long, default_value = "-1d", allow_hyphen_values = true)]
        since: String,
    },
    /// Who the daemon thinks you are.
    Whoami,
    /// Check the setup and print a fix for each problem.
    Doctor,
}

async fn connect(bus: &str) -> Result<zbus::Connection, String> {
    let r = match bus {
        "system" => zbus::Connection::system().await,
        "session" => zbus::Connection::session().await,
        a if a.starts_with("address=") => zbus::connection::Builder::address(&a["address=".len()..]).build().await,
        other => return Err(format!("unknown --bus {other}")),
    };
    r.map_err(|e| format!("cannot reach the {bus} D-Bus: {e}"))
}

async fn call(
    conn: &zbus::Connection,
    iface: &str,
    method: &str,
    args: &(impl serde::Serialize + zbus::zvariant::DynamicType),
) -> Result<String, String> {
    let reply =
        conn.call_method(Some(BUS_NAME), OBJECT_PATH, Some(iface), method, args).await.map_err(|e| explain(&e))?;
    reply.body().deserialize::<String>().map_err(|e| e.to_string())
}

/// Turn a bus error into a sentence with the likely fix.
fn explain(e: &zbus::Error) -> String {
    let text = e.to_string();
    if text.contains("ServiceUnknown") || text.contains("was not provided by any") {
        format!("the Vigil daemon is not running ({text}).\n  Fix: sudo systemctl enable --now vigild   (or for development: vigild --bus session)")
    } else if text.contains("AccessDenied") {
        format!("the daemon said no: {text}")
    } else {
        text
    }
}

/// "-2h", "-30m", "-1d", "-45s" or seconds since the epoch.
fn parse_when(s: &str) -> Result<f64, String> {
    if let Some(rel) = s.strip_prefix('-') {
        let (num, unit) = rel.split_at(rel.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(rel.len()));
        let n: f64 =
            num.parse().map_err(|_| format!("'{s}' is not a time (try -2h, -30m or seconds since the epoch)"))?;
        let mult = match unit {
            "s" | "" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86400.0,
            _ => return Err(format!("unknown unit in '{s}' (s, m, h or d)")),
        };
        return Ok(now() - n * mult);
    }
    s.parse().map_err(|_| format!("'{s}' is not a time (try -2h, -30m or seconds since the epoch)"))
}

fn ago(ts: f64) -> String {
    let d = now() - ts;
    if d < 0.0 {
        "now".into()
    } else {
        format!("{} ago", wording::span(d, true))
    }
}

/// Every cell passes through `printable`: command lines and names are attacker-controlled.
fn cut(s: &str, n: usize) -> String {
    let s = &wording::printable(s);
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
    }
}

fn table(header: &[&str], rows: Vec<Vec<String>>) {
    let rows: Vec<Vec<String>> = rows.into_iter().map(|r| r.iter().map(|c| wording::printable(c)).collect()).collect();
    let mut w: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let last = cells.len() - 1;
        cells
            .into_iter()
            .enumerate()
            .map(|(i, c)| if i == last { c } else { format!("{c:<width$}", width = w[i]) })
            .map(|c| wording::printable(&c))
            .collect::<Vec<_>>()
            .join("  ")
    };
    println!("{}", line(header.iter().map(|h| h.to_string()).collect()));
    for r in rows {
        println!("{}", line(r));
    }
}

/// The everyday name for a program: "Firefox" for well-known ones, otherwise the
/// collector's name ("http.server (python3.13)"). Vigil 1's friendly_program returns
/// "-m" for `python -m module` keys (the first word after the interpreter), so the
/// collector's name, which handles -m and -jar, is preferred whenever it has one.
fn display_name(p: Option<&vigil_model::host::ProcessInfo>, key: &str) -> String {
    let exe = p.and_then(|p| p.exe.as_deref()).unwrap_or(key.split(' ').next().unwrap_or(key));
    let base = exe.rsplit('/').next().unwrap_or(exe).trim_end_matches(" (deleted)").to_lowercase();
    match wording::FRIENDLY.iter().find(|(k, _)| *k == base) {
        Some((_, v)) => v.to_string(),
        None => p.map_or_else(|| wording::friendly_program(None, Some(key), None), |p| p.name.clone()),
    }
}

fn endpoint(ip: &str, port: u32) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    if let Cmd::Doctor = cli.cmd {
        return doctor(&cli.bus).await;
    }
    let conn = connect(&cli.bus).await?;
    match cli.cmd {
        Cmd::Status => {
            let text = call(&conn, IFACE_DAEMON, "Status", &()).await?;
            if cli.json {
                println!("{text}");
                return Ok(());
            }
            let s: DaemonStatus = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            println!("vigild {} (API {}), up {}", s.version, s.api, wording::span(s.uptime_s, false));
            println!("memory {} MB, CPU {:.1} s in total", s.rss_kb / 1024, s.cpu_s);
            println!(
                "store {} (schema {}, {}), keeps {} days; {} programs and {} destinations seen",
                s.store.path,
                s.store.schema,
                wording::kb(s.store.size_bytes as f64),
                s.store.retention_days,
                s.store.programs_seen,
                s.store.destinations_seen
            );
            println!("\nWhat Vigil can and cannot see:");
            for src in s.sources {
                println!(
                    "  {:<12} {:<11} {}",
                    src.signal,
                    if src.live { src.source.clone() } else { "not live".into() },
                    src.note
                );
            }
        }
        Cmd::Processes { filter } => {
            let text = call(&conn, IFACE_PROCESSES, "List", &()).await?;
            if cli.json {
                println!("{text}");
                return Ok(());
            }
            let list: ProcessList = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let f = filter.map(|f| f.to_lowercase());
            let rows: Vec<Vec<String>> = list
                .processes
                .iter()
                .filter(|p| {
                    f.as_ref().is_none_or(|f| {
                        format!("{} {} {}", p.name, p.user, p.cmdline.join(" ")).to_lowercase().contains(f.as_str())
                    })
                })
                .map(|p| {
                    vec![
                        p.pid.to_string(),
                        cut(&p.user, 12),
                        cut(&p.name, 28) + if p.exe_deleted { " (deleted exe)" } else { "" },
                        cut(p.parent.as_deref().unwrap_or("-"), 16),
                        p.started.map_or("-".into(), ago),
                        cut(&p.cmdline.join(" "), 70),
                    ]
                })
                .collect();
            let n = rows.len();
            table(&["PID", "USER", "PROGRAM", "PARENT", "STARTED", "COMMAND"], rows);
            let hidden: usize = list.unreadable_by_uid.values().sum();
            println!(
                "\n{n} of {} processes as seen by the daemon (viewer {}).",
                list.processes.len(),
                list.viewer.user
            );
            if hidden > 0 {
                println!("{hidden} could not be inspected in detail (other users' or protected processes).");
            }
        }
        Cmd::Connections { all } => {
            let text = call(&conn, IFACE_NETWORK, "Snapshot", &()).await?;
            if cli.json {
                println!("{text}");
                return Ok(());
            }
            let snap: NetSnapshot = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let rows: Vec<Vec<String>> = snap
                .sockets
                .iter()
                .filter(|s| {
                    all || (s.kind == "connection" && vigil_model::netaddr::scope_of(&s.remote_ip) != "loopback")
                })
                .map(|s| {
                    let who = match (&s.program, &s.hidden) {
                        (Some(key), _) => {
                            let p = s.pid.and_then(|pid| snap.processes.get(&pid));
                            format!("{} ({})", display_name(p, key), s.pid.map_or(String::new(), |p| p.to_string()))
                        }
                        (None, Some(h)) => h.label.clone(),
                        (None, None) => "-".into(),
                    };
                    vec![
                        s.proto.clone(),
                        if s.kind == "listen" { "listen".into() } else { s.direction.clone() },
                        endpoint(&s.local_ip, s.local_port),
                        endpoint(&s.remote_ip, s.remote_port),
                        s.state.clone(),
                        who,
                    ]
                })
                .collect();
            let n = rows.len();
            table(&["PROTO", "DIR", "LOCAL", "REMOTE", "STATE", "PROGRAM"], rows);
            println!("\n{n} shown of {} sockets (--all includes listening and loopback).", snap.sockets.len());
            for (reason, count) in &snap.hidden_counts {
                println!("{count} {}", vigil_sensor::procfs::hidden_label(reason).to_lowercase());
            }
        }
        Cmd::At { when } => {
            let t = parse_when(&when)?;
            let text = call(&conn, IFACE_NETWORK, "At", &(t,)).await?;
            if cli.json {
                println!("{text}");
                return Ok(());
            }
            let rows: Vec<StoredConnection> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            println!("Open around {} ({}):", t as i64, ago(t));
            let n = rows.len();
            table(
                &["PROTO", "DIR", "REMOTE", "PROGRAM", "OPEN FROM", "UNTIL"],
                rows.into_iter()
                    .map(|c| {
                        vec![
                            c.proto,
                            c.direction,
                            endpoint(&c.remote_ip, c.remote_port),
                            c.program.as_deref().map_or("(not attributed)".into(), |k| display_name(None, k)),
                            ago(c.first_seen),
                            ago(c.last_seen),
                        ]
                    })
                    .collect(),
            );
            if n == 0 {
                println!("Nothing recorded then. History starts when the daemon first ran, and polling misses connections shorter than its interval.");
            }
        }
        Cmd::Events { since } => {
            let t = parse_when(&since)?;
            let text = call(&conn, IFACE_EVENTS, "Since", &(t, 200u32)).await?;
            if cli.json {
                println!("{text}");
                return Ok(());
            }
            let evs: Vec<Event> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            table(
                &["WHEN", "KIND", "WHAT", "FROM"],
                evs.into_iter().map(|e| vec![ago(e.ts), e.kind, e.summary, e.source]).collect(),
            );
        }
        Cmd::Whoami => println!("{}", call(&conn, IFACE_DAEMON, "Whoami", &()).await?),
        Cmd::Doctor => unreachable!(),
    }
    Ok(())
}

/// Each check prints ok, or the problem and its fix. Exit code 1 if anything failed.
async fn doctor(bus: &str) -> Result<(), String> {
    let mut failed = 0;
    let mut say = |ok: bool, what: &str, fix: &str| {
        if ok {
            println!("ok    {what}");
        } else {
            failed += 1;
            println!("FIX   {what}\n      {fix}");
        }
    };
    let k = vigil_sensor::visibility::kernel_facts(std::path::Path::new("/"));
    say(
        k.btf,
        &format!("kernel {} has BTF (needed by the eBPF sensor, milestone 3)", k.release),
        "This kernel was built without CONFIG_DEBUG_INFO_BTF. Vigil falls back to slower sources.",
    );
    if let Some(mode) = &k.lockdown {
        say(
            mode != "confidentiality",
            &format!("kernel lockdown: {mode}"),
            "Lockdown in confidentiality mode blocks eBPF; Vigil uses its fallbacks.",
        );
    }
    let polkit = std::path::Path::new("/usr/share/polkit-1/actions/org.vigil.policy").exists();
    say(polkit, "Vigil's polkit actions are installed", "Install the vigil package (it ships org.vigil.policy).");
    match connect(bus).await {
        Err(e) => say(false, &format!("the {bus} D-Bus"), &e),
        Ok(conn) => {
            say(true, &format!("the {bus} D-Bus is reachable"), "");
            match call(&conn, IFACE_DAEMON, "Whoami", &()).await {
                Err(e) => say(false, "the Vigil daemon answers", &e),
                Ok(w) => {
                    let v: Value = serde_json::from_str(&w).unwrap_or_default();
                    say(
                        true,
                        &format!(
                            "the daemon answers; it sees you as uid {} ({})",
                            v["uid"],
                            v["auth"].as_str().unwrap_or("?")
                        ),
                        "",
                    );
                    match call(&conn, IFACE_DAEMON, "Status", &()).await {
                        Ok(s) => {
                            let s: DaemonStatus = serde_json::from_str(&s).map_err(|e| e.to_string())?;
                            say(s.rss_kb < 60 * 1024, &format!("daemon memory {} MB (budget 60 MB)", s.rss_kb / 1024),
                                "Above the budget: report it with `vigil-cli status --json`.");
                            say(s.store.size_bytes < 2 << 30, &format!("store {} on disk", wording::kb(s.store.size_bytes as f64)),
                                "Lower the retention (vigild --retention-days).");
                        }
                        Err(e) => say(false, "you may read Vigil's data", &format!("{e}\n      polkit decides this (action org.vigil.read): run from your desktop session.")),
                    }
                }
            }
        }
    }
    let clock_ok = now() > 1_700_000_000.0;
    say(clock_ok, "the clock looks right", "Set the time (timedatectl set-ntp true); history is dated by it.");
    if failed > 0 {
        return Err(format!("{failed} thing(s) to fix"));
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vigil-cli: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vigil-cli: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_times_and_cells() {
        let t = parse_when("-2h").unwrap();
        assert!((now() - t - 7200.0).abs() < 2.0);
        assert!((now() - parse_when("-30m").unwrap() - 1800.0).abs() < 2.0);
        assert_eq!(parse_when("1700000000").unwrap(), 1_700_000_000.0);
        assert!(parse_when("-2y").is_err());
        assert!(parse_when("tuesday").is_err());
        assert_eq!(cut("python3 -c \nimport os", 40), "python3 -c ↵import os");
        assert_eq!(cut("abcdef", 4), "abc…");
        assert_eq!(endpoint("::1", 80), "[::1]:80");
    }

    #[test]
    fn display_names_prefer_the_collectors_name_for_scripts() {
        let p = vigil_model::host::ProcessInfo {
            pid: 1,
            key: "/usr/bin/python3 -m http.server".into(),
            name: "http.server (python3)".into(),
            comm: "python3".into(),
            exe: Some("/usr/bin/python3".into()),
            exe_deleted: false,
            cmdline: vec![],
            uid: 0,
            user: "root".into(),
            ppid: 0,
            parent: None,
            ancestry: vec![],
            started: None,
            rss_kb: None,
            cpu_pct: None,
        };
        assert_eq!(display_name(Some(&p), &p.key), "http.server (python3)");
        let ff = vigil_model::host::ProcessInfo { exe: Some("/usr/lib/firefox/firefox".into()), ..p };
        assert_eq!(display_name(Some(&ff), "/usr/lib/firefox/firefox"), "Firefox");
    }
}
