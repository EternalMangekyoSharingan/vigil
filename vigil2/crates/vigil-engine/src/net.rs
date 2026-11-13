//! Vigil 1's network scoring (net/scoring.py) and alert wording (net/wording.py), held to it
//! by tests/golden/net.json.
//!
//! A score belongs to a *pair*: one program talking to one address on one service port in one
//! direction. It is the sum of scored observations, each with its points, a plain-language
//! reason, the check that produced it and the data it used. A beacon alone (at most 65 points)
//! stays below the alert threshold on purpose: plenty of legitimate software polls on a timer.
//! Only pairs at or above [`ALERT_THRESHOLD`] that no allowlist rule covers become alerts.
//!
//! Not ported yet: byte counts (Vigil 2 has no sock_diag source yet, so "similar size each
//! time" never fires), names, owners and countries of addresses (no offline databases yet),
//! known-service matches and threat feeds.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use vigil_model::finding::{scored, Scored};
use vigil_model::netaddr::{in_network, is_private, scope_of};
use vigil_model::wording::{every, fit_title, friendly_program, kb, py_round, span, TITLE_MAX};

pub const ALERT_THRESHOLD: f64 = 70.0;
pub const LOOKBACK: f64 = 24.0 * 3600.0;
pub const RECENT: f64 = 24.0 * 3600.0;
const MIN_CHECKINS: usize = 6;
const MAX_MISSED_RUN: i64 = 5;
const CV_PERIODIC: f64 = 0.20;
const CV_CEILING: f64 = 0.35;
const LONG_MIN: f64 = 3600.0;
const LONG_MAX: f64 = 8.0 * 3600.0;

fn points(check: &str) -> f64 {
    match check {
        "beacon_regularity" => 45.0,
        "beacon_persistence"
        | "beacon_size"
        | "uncommon_port"
        | "hidden_dir_executable"
        | "deleted_executable"
        | "rare_country" => 10.0,
        "long_connection" => 30.0,
        "new_destination" => 15.0,
        "new_program" => 20.0,
        "rare_destination" => 5.0,
        "temp_executable" => 25.0,
        _ => 0.0,
    }
}

const COMMON_PORTS: [u32; 25] = [
    20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 1900, 3478, 5222, 5228, 5353, 8080,
    8443, 19302,
];
const TEMP_DIRS: [&str; 4] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
const HIDDEN_DIR_OK: &[&str] = &[
    ".local",
    ".cargo",
    ".rustup",
    ".nvm",
    ".npm",
    ".pyenv",
    ".sdkman",
    ".deno",
    ".bun",
    ".var",
    ".vscode",
    ".vscode-server",
    ".vscode-oss",
    ".cursor",
    ".cursor-server",
    ".steam",
    ".linuxbrew",
    ".dotnet",
    ".gem",
    ".rbenv",
    ".juliaup",
    ".ghcup",
    ".opam",
    ".nix-profile",
    ".mozilla",
];

// ---- time and number formatting, as Vigil 1 prints them --------------------------------

/// (year, month, day) for days since 1970-01-01.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Local time parts of `ts` for a UTC offset in seconds: (days, hour, minute, second).
fn parts(ts: f64, off: i64) -> (i64, i64, i64, i64) {
    let t = ts.floor() as i64 + off;
    (t.div_euclid(86_400), t.rem_euclid(86_400) / 3600, t.rem_euclid(3600) / 60, t.rem_euclid(60))
}

/// "14:05:09" (net/scoring.py `clock`).
pub fn clock_s(ts: f64, off: i64) -> String {
    let (_, h, m, s) = parts(ts, off);
    format!("{h:02}:{m:02}:{s:02}")
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// "03:34" today, "Oct 30, 21:42" otherwise (core/wording.py `clock`).
pub fn clock_hm(ts: f64, now: f64, off: i64) -> String {
    let (d, h, m, _) = parts(ts, off);
    let (dn, ..) = parts(now, off);
    if d == dn {
        return format!("{h:02}:{m:02}");
    }
    let (_, mo, day) = civil(d);
    format!("{} {:02}, {h:02}:{m:02}", MONTHS[(mo - 1) as usize], day).replace(" 0", " ")
}

/// "2026-11-09 14:05".
fn date_time(ts: f64, off: i64) -> String {
    let (d, h, m, _) = parts(ts, off);
    let (y, mo, day) = civil(d);
    format!("{y:04}-{mo:02}-{day:02} {h:02}:{m:02}")
}

/// "5s", "3m 20s", "2h 5m" (net/store.py `fmt_duration`).
pub fn fmt_duration(seconds: f64) -> String {
    let s = seconds.max(0.0) as i64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{}h {}m", s / 3600, s % 3600 / 60)
    }
}

fn fmt_interval(seconds: f64) -> String {
    if seconds < 120.0 {
        format!("{} s", py_round(seconds))
    } else {
        fmt_duration(seconds)
    }
}

pub fn fmt_endpoint(ip: &str, port: u32) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn fmt_bytes(n: f64) -> String {
    let mut n = n;
    for unit in ["B", "kB", "MB", "GB"] {
        if n < 1000.0 || unit == "GB" {
            return if unit == "B" { format!("{} {unit}", py_round(n)) } else { format!("{n:.1} {unit}") };
        }
        n /= 1000.0;
    }
    format!("{n} B")
}

/// Python's `{x:g}` for the poll interval (2.0 -> "2", 0.5 -> "0.5").
fn g(x: f64) -> String {
    if x.fract() == 0.0 {
        format!("{}", x as i64)
    } else {
        format!("{x}")
    }
}

fn clamp(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

fn fmean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn pstdev(v: &[f64]) -> f64 {
    let m = fmean(v);
    (v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / v.len() as f64).sqrt()
}

fn r1(x: f64) -> f64 {
    vigil_model::finding::round_to(x, 1)
}

// ---- individual checks -------------------------------------------------------------------

/// One connection of a pair, as the store keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conn {
    pub id: i64,
    pub opened_at: f64,
    pub closed_at: Option<f64>,
    #[serde(default)]
    pub bytes_sent: Option<f64>,
    #[serde(default)]
    pub bytes_recv: Option<f64>,
    #[serde(default)]
    pub local_port: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconStats {
    pub checkins: usize,
    pub missed: i64,
    pub interval: f64,
    pub cv: f64,
    pub first: f64,
    pub last: f64,
    pub samples: usize,
    pub pauses: Vec<f64>,
}

/// Regularity of a pair's connection start times, or None if there is too little.
///
/// Starts closer together than 1.5 poll intervals are one check-in. An interval close to a
/// small whole multiple of the median is check-ins the poller missed; a much longer silence
/// (sleep, restart) is a pause, left out of the statistics and reported.
pub fn beacon_stats(times: &[f64], poll: f64) -> Option<BeaconStats> {
    let mut sorted = times.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mut checkins: Vec<f64> = vec![];
    for t in sorted {
        if checkins.last().is_none_or(|l| t - l > 1.5 * poll) {
            checkins.push(t);
        }
    }
    if checkins.len() < MIN_CHECKINS {
        return None;
    }
    let raw: Vec<f64> = checkins.windows(2).map(|w| w[1] - w[0]).collect();
    let med = median(&raw);
    if med < 3.0 * poll {
        return None;
    }
    let (mut intervals, mut missed, mut pauses) = (vec![], 0i64, vec![]);
    for x in raw {
        let k = py_round(x / med);
        if k > MAX_MISSED_RUN + 1 {
            pauses.push(x);
        } else if k >= 2 && (x / k as f64 - med).abs() <= 0.15 * med {
            intervals.extend(std::iter::repeat_n(x / k as f64, k as usize));
            missed += k - 1;
        } else {
            intervals.push(x);
        }
    }
    if intervals.len() + 1 < MIN_CHECKINS {
        return None;
    }
    let mean = fmean(&intervals);
    Some(BeaconStats {
        checkins: checkins.len(),
        missed,
        interval: mean,
        cv: pstdev(&intervals) / mean,
        first: checkins[0],
        last: *checkins.last().unwrap_or(&0.0),
        samples: intervals.len() + 1 + pauses.len(),
        pauses,
    })
}

fn keep_positive(v: Vec<Scored>) -> Vec<Scored> {
    v.into_iter().filter(|f| f.points > 0.0).collect()
}

/// Beacon findings for one outbound pair's connections.
pub fn beacon_findings(conns: &[Conn], poll: f64, endpoint: &str, off: i64) -> Vec<Scored> {
    let times: Vec<f64> = conns.iter().map(|c| c.opened_at).collect();
    let Some(b) = beacon_stats(&times, poll) else { return vec![] };
    if b.cv >= CV_CEILING {
        return vec![];
    }
    let mut out = vec![];
    let pct = py_round(b.cv * 100.0);
    let kind = if b.cv < CV_PERIODIC { "Periodic" } else { "Loosely periodic" };
    let mut missed = if b.missed > 0 { format!("; {} probably missed between polls", b.missed) } else { String::new() };
    if !b.pauses.is_empty() {
        let longest = b.pauses.iter().cloned().fold(f64::MIN, f64::max);
        missed += &format!(
            "; {} pause{} (longest {}) left out",
            b.pauses.len(),
            if b.pauses.len() > 1 { "s" } else { "" },
            fmt_duration(longest)
        );
    }
    let data = format!(
        "connections table: {} connections to {endpoint} opened {}–{}, start times measured to ±{} s",
        conns.len(),
        clock_s(b.first, off),
        clock_s(b.last, off),
        g(poll)
    );
    out.push(scored(
        "beacon",
        points("beacon_regularity") * clamp((CV_CEILING - b.cv) / (CV_CEILING - 0.05)),
        &format!(
            "{kind}: every {} ± {pct}% (coefficient of variation {:.2} over {} check-ins{missed})",
            fmt_interval(b.interval),
            b.cv,
            b.checkins
        ),
        json!(data),
        None,
        Some(json!({
            "signal": "timer", "interval": r1(b.interval), "cv": vigil_model::finding::round_to(b.cv, 3),
            "checkins": b.checkins, "missed": b.missed,
            "pauses": b.pauses.iter().map(|x| py_round(*x)).collect::<Vec<_>>(),
            "first": b.first, "last": b.last, "connections": conns.len(), "poll": poll,
        })),
    ));
    let span_s = b.last - b.first;
    out.push(scored(
        "beacon",
        points("beacon_persistence") * clamp((b.samples as f64 - MIN_CHECKINS as f64) / 24.0),
        &format!("Kept up for {} ({} check-ins counting missed ones)", fmt_duration(span_s), b.samples),
        json!(data),
        None,
        Some(json!({"signal": "duration", "span": py_round(span_s), "samples": b.samples, "first": b.first, "last": b.last})),
    ));
    let sizes: Vec<f64> = conns
        .iter()
        .filter(|c| c.closed_at.is_some())
        .filter_map(|c| Some(c.bytes_sent? + c.bytes_recv.unwrap_or(0.0)))
        .collect();
    if sizes.len() >= 5 && fmean(&sizes) > 0.0 {
        let mean = fmean(&sizes);
        let scv = pstdev(&sizes) / mean;
        if scv < CV_CEILING {
            out.push(scored(
                "beacon",
                points("beacon_size") * clamp((CV_CEILING - scv) / (CV_CEILING - 0.10)),
                &format!("Similar size each time: ≈ {} ± {}%", fmt_bytes(mean), py_round(scv * 100.0)),
                json!(format!(
                    "sock_diag byte counts of {} closed connections (last poll before close, so slightly low)",
                    sizes.len()
                )),
                None,
                Some(json!({"signal": "same_size", "mean": py_round(mean), "cv": vigil_model::finding::round_to(scv, 3), "n": sizes.len()})),
            ));
        }
    }
    keep_positive(out)
}

pub fn long_connection_finding(conns: &[Conn], now: f64, baseline: Option<f64>, off: i64) -> Option<Scored> {
    let dur = |c: &Conn| c.closed_at.unwrap_or(now) - c.opened_at;
    let mut best = conns.first()?;
    for c in conns {
        if dur(c) > dur(best) {
            best = c;
        }
    }
    let d = dur(best);
    if d < LONG_MIN {
        return None;
    }
    let pts = points("long_connection") * (0.5 + 0.5 * clamp((d - LONG_MIN) / (LONG_MAX - LONG_MIN)));
    let at_least = baseline.is_some_and(|b| best.opened_at <= b);
    let state = match best.closed_at {
        None => "still open".to_string(),
        Some(c) => format!("closed {}", clock_s(c, off)),
    };
    Some(scored(
        "long_connection",
        pts,
        &format!(
            "One connection open {}{} (since {}, {state})",
            if at_least { "at least " } else { "" },
            fmt_duration(d),
            clock_s(best.opened_at, off)
        ),
        json!(format!("connections table: connection #{}, local port {}", best.id, best.local_port)),
        None,
        Some(json!({
            "signal": "long", "duration": py_round(d), "opened_at": best.opened_at,
            "closed_at": best.closed_at, "at_least": at_least,
        })),
    ))
}

/// What the scorer knows about the program behind a pair (from its last look).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProgInfo {
    #[serde(default)]
    pub exe: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub exe_deleted: bool,
}

/// Where the program runs from: temporary folders, hidden folders, deleted files.
pub fn location_findings(info: &ProgInfo, key: &str) -> Vec<Scored> {
    let mut out = vec![];
    let exe = info.exe.clone().unwrap_or_default();
    let mut paths = vec![exe.strip_suffix(" (deleted)").unwrap_or(&exe).to_string()];
    let script = key.split_once(' ').map_or("", |(_, s)| s);
    if script.starts_with('/') {
        paths.push(script.to_string());
    }
    let pid = info.pid.map_or("None".to_string(), |p| p.to_string());
    let src = json!(format!("/proc/{pid}/exe and cmdline at last poll"));
    for path in &paths {
        if TEMP_DIRS.iter().any(|t| path.starts_with(t)) {
            out.push(scored(
                "process_location",
                points("temp_executable"),
                &format!(
                    "Runs from {path}: a world-writable temporary directory, a common drop location for downloaded payloads"
                ),
                src.clone(),
                None,
                Some(json!({"signal": "temp_dir", "path": path})),
            ));
            break;
        }
        let parts: Vec<&str> = path.split('/').collect();
        let hidden: Vec<&str> = if parts.len() > 2 {
            parts[1..parts.len() - 1].iter().copied().filter(|p| p.starts_with('.')).collect()
        } else {
            vec![]
        };
        if let Some(first) = hidden.first() {
            if !HIDDEN_DIR_OK.contains(first) {
                out.push(scored(
                    "process_location",
                    points("hidden_dir_executable"),
                    &format!("Runs from a hidden directory ({path})"),
                    src.clone(),
                    None,
                    Some(json!({"signal": "hidden_dir", "path": path})),
                ));
                break;
            }
        }
    }
    if info.exe_deleted {
        out.push(scored(
            "process_location",
            points("deleted_executable"),
            "Its executable was deleted or replaced while running. Normal right after a package upgrade; otherwise a way to leave no file behind",
            src,
            None,
            Some(json!({"signal": "deleted_exe"})),
        ));
    }
    out
}

// ---- allowlist ----------------------------------------------------------------------------

/// One allowlist rule. Program patterns match the real executable path, so a copy of an
/// allowlisted program placed somewhere else does not match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub port: Option<u32>,
    #[serde(default)]
    pub proto: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
    pub reason: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

pub fn builtin_rules() -> Vec<Rule> {
    let r = |id: &str,
             program: Option<&str>,
             ip: Option<&str>,
             port: Option<u32>,
             proto: Option<&str>,
             dir: Option<&str>,
             reason: &str| Rule {
        id: id.into(),
        program: program.map(String::from),
        ip: ip.map(String::from),
        port,
        proto: proto.map(String::from),
        direction: dir.map(String::from),
        reason: reason.into(),
        enabled: true,
    };
    vec![
        r(
            "builtin-loopback",
            None,
            Some("loopback"),
            None,
            None,
            None,
            "Traffic between programs on this machine never leaves it.",
        ),
        r(
            "builtin-ntp",
            None,
            None,
            Some(123),
            Some("udp"),
            Some("out"),
            "Time sync (NTP) checks in on a timer by design.",
        ),
        r(
            "builtin-dns-lan",
            None,
            Some("lan"),
            Some(53),
            None,
            Some("out"),
            "DNS lookups to a resolver on the local network.",
        ),
        r(
            "builtin-mdns",
            None,
            Some("multicast"),
            Some(5353),
            None,
            None,
            "Local service discovery (mDNS) is periodic by design.",
        ),
        r(
            "builtin-networkmanager",
            Some("/usr/*bin/NetworkManager"),
            None,
            None,
            None,
            Some("out"),
            "NetworkManager's connectivity check polls on a timer.",
        ),
        r(
            "builtin-timesync",
            Some("/usr/lib/systemd/systemd-timesyncd"),
            None,
            None,
            None,
            Some("out"),
            "systemd's time sync daemon.",
        ),
        r("builtin-chrony", Some("/usr/*bin/chronyd"), None, None, None, Some("out"), "chrony time sync daemon."),
        r(
            "builtin-packagekit",
            Some("/usr/lib*/packagekit*"),
            None,
            None,
            None,
            Some("out"),
            "PackageKit checks for updates periodically.",
        ),
        r(
            "builtin-snapd",
            Some("/usr/lib/snapd/snapd"),
            None,
            None,
            None,
            Some("out"),
            "snapd refreshes snaps periodically.",
        ),
        r(
            "builtin-fwupd",
            Some("/usr/lib*/fwupd*"),
            None,
            None,
            None,
            Some("out"),
            "fwupd checks for firmware metadata periodically.",
        ),
        r("builtin-apt", Some("/usr/lib/apt/methods/*"), None, None, None, Some("out"), "APT package downloads."),
    ]
}

const SCOPES: [&str; 6] = ["internet", "lan", "loopback", "link-local", "multicast", "reserved"];

/// Python's `fnmatch.fnmatchcase`: `*`, `?`, `[seq]` and `[!seq]` (a `*` matches `/` too).
pub fn fnmatch(name: &str, pat: &str) -> bool {
    let n: Vec<char> = name.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    fn class(p: &[char], i: usize, c: char) -> Option<(bool, usize)> {
        // Returns (matched, index after ']'), or None if the bracket is not closed.
        let mut j = i + 1;
        let neg = p.get(j) == Some(&'!');
        if neg {
            j += 1;
        }
        let start = j;
        let mut hit = false;
        while j < p.len() && (p[j] != ']' || j == start) {
            if j + 2 < p.len() && p[j + 1] == '-' && p[j + 2] != ']' {
                if p[j] <= c && c <= p[j + 2] {
                    hit = true;
                }
                j += 3;
            } else {
                if p[j] == c {
                    hit = true;
                }
                j += 1;
            }
        }
        (j < p.len()).then_some((hit != neg, j + 1))
    }
    fn go(n: &[char], p: &[char], i: usize, j: usize) -> bool {
        if j == p.len() {
            return i == n.len();
        }
        match p[j] {
            '*' => (i..=n.len()).any(|k| go(n, p, k, j + 1)),
            '?' => i < n.len() && go(n, p, i + 1, j + 1),
            '[' => match class(p, j, *n.get(i).unwrap_or(&'\0')) {
                Some((m, next)) => i < n.len() && m && go(n, p, i + 1, next),
                None => i < n.len() && n[i] == '[' && go(n, p, i + 1, j + 1),
            },
            c => i < n.len() && n[i] == c && go(n, p, i + 1, j + 1),
        }
    }
    go(&n, &p, 0, 0)
}

/// The pair a score belongs to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pair {
    pub program: String,
    pub ip: String,
    pub port: u32,
    pub proto: String,
    pub direction: String,
    #[serde(default)]
    pub scope: String,
}

pub fn rule_matches(rule: &Rule, pair: &Pair) -> bool {
    if !fnmatch(&pair.program, rule.program.as_deref().unwrap_or("*")) {
        return false;
    }
    let ip = rule.ip.as_deref().unwrap_or("*");
    if SCOPES.contains(&ip) {
        if scope_of(&pair.ip) != ip {
            return false;
        }
    } else if ip != "*" && in_network(&pair.ip, ip) != Some(true) {
        return false;
    }
    rule.port.is_none_or(|p| p == pair.port)
        && rule.proto.as_deref().is_none_or(|p| p == "*" || p == pair.proto)
        && rule.direction.as_deref().is_none_or(|d| d == "*" || d == pair.direction)
}

pub fn first_match<'a>(rules: &'a [Rule], pair: &Pair) -> Option<&'a Rule> {
    rules.iter().find(|r| r.enabled && rule_matches(r, pair))
}

// ---- scoring a pair -----------------------------------------------------------------------

/// A program as the store remembers it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProgramRow {
    pub name: String,
    /// When it first used the network (Vigil 1's first outbound connection).
    pub first_outbound: Option<f64>,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub info: ProgInfo,
}

/// What one scoring run knows besides the pair's own connections.
pub struct Context {
    pub now: f64,
    /// When Vigil started watching (anything before is not "new").
    pub baseline: Option<f64>,
    pub programs: HashMap<String, ProgramRow>,
    /// Per destination address: its first sighting and the scope stored with it.
    pub destinations: HashMap<String, (f64, String)>,
    /// Per address: (programs that ever contacted it, connections to it).
    pub prevalence: HashMap<String, (usize, usize)>,
    pub poll: f64,
    /// Seconds east of UTC, for clock times in the words.
    pub utc_offset: i64,
}

/// Score one pair: (pair, score, scored observations), in Vigil 1's order.
pub fn score_pair(key: (&str, &str, u32, &str, &str), conns: &[Conn], cx: &Context) -> (Pair, f64, Vec<Scored>) {
    let (program, ip, port, proto, direction) = key;
    let prog = cx.programs.get(program);
    let now = cx.now;
    let pair = Pair {
        program: program.into(),
        ip: ip.into(),
        port,
        proto: proto.into(),
        direction: direction.into(),
        scope: cx
            .destinations
            .get(ip)
            .map(|d| d.1.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| scope_of(ip).into()),
    };
    let mut out = vec![];
    if direction == "out" {
        out.extend(beacon_findings(conns, cx.poll, &format!("{proto} {}", fmt_endpoint(ip, port)), cx.utc_offset));
    }
    if let Some(l) = long_connection_finding(conns, now, cx.baseline, cx.utc_offset) {
        out.push(l);
    }
    if let (Some(base), Some((first, _))) = (cx.baseline, cx.destinations.get(ip)) {
        if *first > base && now - first < RECENT {
            out.push(scored(
                "first_seen",
                points("new_destination"),
                &format!(
                    "New destination: first contacted at {}, after Vigil's baseline of {}",
                    clock_s(*first, cx.utc_offset),
                    date_time(base, cx.utc_offset)
                ),
                json!("destinations table (first-seen tracking)"),
                None,
                Some(json!({"signal": "new_destination", "at": first, "baseline": base})),
            ));
        }
    }
    if let (Some(p), Some(base)) = (prog, cx.baseline) {
        let first = p.first_outbound.unwrap_or(0.0);
        if direction == "out" && !p.hidden && first > base && now - first < RECENT {
            out.push(scored(
                "first_seen",
                points("new_program"),
                &format!(
                    "This program made its first outbound connection at {}; it had not used the network since Vigil started watching",
                    clock_s(first, cx.utc_offset)
                ),
                json!("programs table (first outbound connection)"),
                None,
                Some(json!({"signal": "new_program", "at": first})),
            ));
        }
    }
    let prev = cx.prevalence.get(ip).copied().unwrap_or((0, 0));
    if pair.scope == "internet" && prev.0 <= 1 && prev.1 <= 5 {
        out.push(scored(
            "rarity",
            points("rare_destination"),
            &format!(
                "Rare: only this program has ever contacted this address ({} connection{} in Vigil's history)",
                prev.1,
                if prev.1 != 1 { "s" } else { "" }
            ),
            json!("pairs table (all programs, all time)"),
            None,
            Some(json!({"signal": "rare", "programs": prev.0, "connections": prev.1})),
        ));
    }
    if !COMMON_PORTS.contains(&port) && pair.scope != "loopback" {
        out.push(scored(
            "uncommon_port",
            points("uncommon_port"),
            &format!("{proto}/{port} is not a common service port"),
            json!(format!("connections table: {} port", if direction == "in" { "local" } else { "remote" })),
            None,
            Some(json!({"signal": "odd_port", "port": port, "proto": proto})),
        ));
    }
    if let Some(p) = prog.filter(|p| !p.hidden) {
        out.extend(location_findings(&p.info, program));
    } else if prog.is_none() {
        out.extend(location_findings(&ProgInfo::default(), program));
    }
    for f in &mut out {
        f.at = Some(now);
    }
    let score = r1(out.iter().map(|f| f.points).sum::<f64>()).min(100.0);
    (pair, score, out)
}

// ---- the words of an alert (net/wording.py) ------------------------------------------------

/// Everything an alert says, from its pair and scored observations.
pub struct Alert<'a> {
    pub pair: &'a Pair,
    pub score: f64,
    pub findings: &'a [Scored],
    pub name: Option<&'a str>,
    pub exe: Option<&'a str>,
    /// Why the program is unknown ("closed", "other-user" ...), or None.
    pub hidden: Option<&'a str>,
    pub first_raised: f64,
    pub now: f64,
    pub utc_offset: i64,
}

const UNKNOWN_WHO: &str = "An unidentified program";

fn max_points(kind: &str) -> f64 {
    match kind {
        "timer" => 45.0,
        "long" => 30.0,
        "new_destination" => 15.0,
        "new_program" => 20.0,
        "rare" => 5.0,
        "temp_dir" => 25.0,
        "threat" => 100.0,
        "duration" | "same_size" | "odd_port" | "hidden_dir" | "deleted_exe" | "new_country" => 10.0,
        _ => 50.0,
    }
}

fn signal_of(f: &Scored) -> Option<&str> {
    f.stats.as_ref()?.get("signal")?.as_str()
}

fn stat(f: &Scored, k: &str) -> f64 {
    f.stats.as_ref().and_then(|s| s.get(k)).and_then(Value::as_f64).unwrap_or(0.0)
}

impl Alert<'_> {
    fn sig(&self, kind: &str) -> Option<&Scored> {
        // The last observation of a kind wins, as in Vigil 1's dict.
        self.findings.iter().rev().find(|f| signal_of(f) == Some(kind))
    }

    fn has(&self, kind: &str) -> bool {
        self.sig(kind).is_some()
    }

    pub fn who(&self) -> Option<String> {
        if self.hidden.is_some() {
            return None;
        }
        Some(friendly_program(self.exe, Some(&self.pair.program), self.name))
    }

    /// To whom: without names or owners yet, a short address or "this PC".
    pub fn to(&self) -> String {
        let ip = &self.pair.ip;
        if self.pair.scope == "loopback" {
            return "this PC".into();
        }
        let Ok(a) = ip.parse::<std::net::IpAddr>() else { return "a server".into() };
        if self.pair.scope == "lan" || is_private(ip) {
            return if a.is_ipv6() { "a device on your network".into() } else { format!("{ip} on your network") };
        }
        if a.is_ipv4() {
            ip.clone()
        } else {
            "an IPv6 server".into()
        }
    }

    fn plain_http(&self) -> bool {
        self.pair.proto == "tcp" && matches!(self.pair.port, 80 | 8080) && self.pair.direction == "out"
    }

    fn phrasings(&self, who: &str, to: &str, freq: Option<&str>) -> Vec<String> {
        let mut out = vec![];
        if self.pair.direction == "in" {
            out.push(format!("{to} connects in to {who}{}", freq.map_or(String::new(), |f| format!(" {f}"))));
            out.push(format!("{who} accepts connections from {to}"));
        }
        if let Some(f) = freq {
            if self.plain_http() {
                out.push(format!("{who} sends plain HTTP to {to} {f}"));
                out.push(format!("{who} sends plain HTTP {f}"));
            }
            out.push(format!("{who} checks in with {to} {f}"));
            out.push(format!("{who} checks in {f}"));
        }
        if let Some(l) = self.sig("long") {
            let d = span(stat(l, "duration"), true);
            out.push(format!("{who} keeps a connection to {to} open for {d}"));
            out.push(format!("{who} keeps a connection open for {d}"));
        }
        if self.has("temp_dir") {
            out.push(format!("A program in a temp folder contacts {to}"));
            out.push(format!("{who} runs from a temp folder"));
        }
        if self.has("new_program") {
            out.push(format!("{who} went online for the first time, to {to}"));
            out.push(format!("{who} went online for the first time"));
        }
        if self.has("new_destination") {
            out.push(format!("{who} contacted {to} for the first time"));
            out.push(format!("{who} contacted a new server"));
        }
        out.push(format!("{who} talks to {to}"));
        out.push(format!("{who} talks to a server"));
        out
    }

    pub fn title(&self) -> String {
        let freq = self.sig("timer").map(|t| every(stat(t, "interval")));
        let whos = match self.who() {
            Some(w) => vec![w],
            None => vec![UNKNOWN_WHO.to_string(), "Unidentified program".to_string()],
        };
        let to = self.to();
        let mut candidates = vec![];
        for w in &whos {
            for t in [&to, &to] {
                candidates.extend(self.phrasings(w, t, freq.as_deref()));
            }
        }
        fit_title(&candidates, TITLE_MAX)
    }

    pub fn severity(&self) -> &'static str {
        if self.score >= 90.0 {
            "High"
        } else {
            "Medium"
        }
    }

    pub fn summary(&self) -> String {
        let who = self.who().unwrap_or_else(|| "A program Vigil could not identify".into());
        let to = self.to();
        if let Some(t) = self.sig("timer") {
            let how = if self.plain_http() { "over plain HTTP " } else { "" };
            return format!(
                "{who} has contacted {to} {how}about {} since {}.",
                every(stat(t, "interval")).replace("every ~", "every "),
                clock_hm(stat(t, "first"), self.now, self.utc_offset)
            );
        }
        if let Some(l) = self.sig("long") {
            return format!("{who} has kept one connection to {to} open for {}.", span(stat(l, "duration"), false));
        }
        if self.has("temp_dir") {
            return format!("{who} runs from a temporary folder and talks to {to}.");
        }
        format!("{who} talks to {to} in a way Vigil found unusual.")
    }

    fn signal_line(&self, f: &Scored) -> Option<String> {
        let kind = signal_of(f)?;
        let s = |k: &str| stat(f, k);
        let txt = |k: &str| f.stats.as_ref().and_then(|x| x.get(k)).and_then(Value::as_str).unwrap_or("").to_string();
        Some(match kind {
            "timer" => {
                let cv = s("cv");
                let reg = if cv < 0.1 {
                    "very regular"
                } else if cv < 0.2 {
                    "regular"
                } else {
                    "fairly regular"
                };
                format!(
                    "Contacts it on a steady timer ({}, {reg})",
                    every(s("interval")).replace("every ~", "about every ")
                )
            }
            "duration" => format!("Has kept this up for {}", span(s("span"), false)),
            "same_size" => format!("Sends about the same amount each time ({})", kb(s("mean"))),
            "long" => {
                let more = f.stats.as_ref().and_then(|x| x.get("at_least")).and_then(Value::as_bool).unwrap_or(false);
                format!(
                    "Has kept one connection open for {}{}",
                    span(s("duration"), false),
                    if more { " or more" } else { "" }
                )
            }
            "new_destination" => "First time this PC has talked to this server since Vigil started watching".into(),
            "new_program" => "First time this program used the network since Vigil started watching".into(),
            "rare" => "No other program on this PC talks to this server".into(),
            "odd_port" => format!("Uses port {}, which no common service uses", s("port") as i64),
            "temp_dir" => format!("Runs from a temporary folder ({}), where downloads land", txt("path")),
            "hidden_dir" => format!("Runs from a hidden folder ({})", txt("path")),
            "deleted_exe" => "Its program file was deleted or replaced while it ran".into(),
            _ => return None,
        })
    }

    /// The signals as Vigil 1 explains them: (signal, text, strength), strongest first.
    pub fn signals(&self) -> Vec<(String, String, f64)> {
        let mut fs: Vec<&Scored> = self.findings.iter().collect();
        fs.sort_by(|a, b| b.points.partial_cmp(&a.points).unwrap_or(std::cmp::Ordering::Equal));
        let mut lines = vec![];
        for f in fs {
            let kind = signal_of(f);
            match (kind, self.signal_line(f)) {
                (Some(k), Some(text)) => {
                    let strength = if f.points > 0.0 { (f.points / max_points(k)).min(1.0) } else { 0.0 };
                    lines.push((k.to_string(), text, vigil_model::finding::round_to(strength, 2)));
                }
                _ if f.points > 0.0 => {
                    let text = f.reason.split(" (").next().unwrap_or(&f.reason).to_string();
                    lines.push((f.check.clone(), text, vigil_model::finding::round_to((f.points / 50.0).min(1.0), 2)));
                }
                _ => {}
            }
        }
        if self.plain_http() {
            lines.push((
                "plain_http".into(),
                "Uses unencrypted HTTP, so anyone on the network path can read it".into(),
                0.5,
            ));
        }
        if let Some(h) = self.hidden {
            let why = match h {
                "closed" => "the connection closed before Vigil could see which program owned it",
                "other-user" => "it runs as another user (often root), whose programs a normal user cannot see",
                "protected" => "the system protects that process from being inspected",
                _ => "no visible process held the connection",
            };
            lines.push(("unattributed".into(), format!("Vigil could not see which program this is: {why}"), 0.3));
        }
        lines
    }

    /// Why each kind of signal matters, once per group, in the order they appear.
    pub fn why(&self) -> Vec<(String, String)> {
        let group = |k: &str| match k {
            "timer" | "duration" | "same_size" => Some("timer"),
            "long" => Some("long"),
            "new_destination" | "new_program" => Some("new"),
            "rare" => Some("rare"),
            "odd_port" => Some("odd_port"),
            "temp_dir" | "hidden_dir" | "deleted_exe" => Some("location"),
            "threat" => Some("threat"),
            "new_country" => Some("country"),
            "plain_http" => Some("plain_http"),
            "unattributed" => Some("unattributed"),
            _ => None,
        };
        let text = |g: &str| {
            match g {
            "timer" => "Updaters, sync tools and chat apps do this. So does malware checking in with its owner. A timer alone is never enough to raise an alert.",
            "long" => "Chat apps, sync tools and VPNs keep connections open for hours. So do remote-control tools.",
            "new" => "Most new things are harmless: a new app or a new website. But almost everything bad is new too.",
            "rare" => "Popular servers are shared by many programs. One only this program uses is worth a look.",
            "odd_port" => "Most software uses a few well-known ports. Odd ones are often games or file sharing, sometimes backdoors.",
            "location" => "Installed software lives in /usr or /opt. Temporary and hidden folders are where downloaded payloads hide.",
            "plain_http" => "Anyone between you and the server can read or change unencrypted traffic. Some background checks still use it on purpose, because they carry nothing private.",
            _ => "Vigil reads the system every couple of seconds as your user. Very short connections, or ones owned by root, can come and go before Vigil sees their owner.",
        }
        };
        let mut out: Vec<(String, String)> = vec![];
        for (k, _, _) in self.signals() {
            if let Some(g) = group(&k) {
                if !out.iter().any(|(x, _)| x == g) {
                    out.push((g.to_string(), text(g).to_string()));
                }
            }
        }
        out
    }

    pub fn confidence(&self) -> (&'static str, &'static str) {
        let kinds: Vec<&str> = self.findings.iter().filter_map(signal_of).collect();
        let mut distinct: Vec<&str> = vec![];
        for k in kinds {
            if !distinct.contains(&k) {
                distinct.push(k);
            }
        }
        if self.has("temp_dir") && (self.has("timer") || self.has("new_program")) {
            ("High", "A program running from a temporary folder that phones home is a classic malware pattern.")
        } else if distinct.iter().filter(|k| !matches!(**k, "duration" | "same_size")).count() >= 3 {
            ("Medium", "Several separate signals point the same way, but none of them is conclusive.")
        } else {
            ("Low", "Only common patterns, each with innocent explanations.")
        }
    }

    /// ATT&CK techniques the signals suggest (net/export.py `_attack`).
    pub fn attack(&self) -> Vec<&'static str> {
        let mut out = vec![];
        if matches!(self.pair.port, 80 | 443 | 8080 | 8443) {
            out.push("T1071.001");
        }
        if self.has("timer") {
            out.push("T1029");
        }
        if self.has("odd_port") {
            out.push("T1571");
        }
        if self.has("temp_dir") || self.has("hidden_dir") {
            out.push("T1564.001");
        }
        if self.has("deleted_exe") {
            out.push("T1070.004");
        }
        out
    }

    /// The alert as a finding (net/export.py `to_finding`), with read-only checks to copy.
    pub fn finding(
        &self,
        osr: &vigil_model::distro::OsRelease,
    ) -> Result<vigil_model::finding::Finding, vigil_model::finding::FindingError> {
        use vigil_model::fixes::{option, panel, Risk};
        let p = self.pair;
        let fingerprint = format!("{}|{}|{}", p.program, p.ip, p.direction);
        let mut summary = self.summary();
        if !vigil_model::wording::one_sentence(&summary) {
            summary = format!("{}.", summary.split(". ").next().unwrap_or(&summary).trim_end_matches('.'));
        }
        let (level, reason) = self.confidence();
        let mut b = vigil_model::finding::Builder::new("net", "alert", &self.title(), &summary, self.severity());
        for (k, text, strength) in self.signals() {
            b = b.signal_kind(&text, strength, &k);
        }
        let endpoint = fmt_endpoint(&p.ip, p.port);
        let check = vec![
            option(
                "Which program has it open now",
                "Lists open connections to this address with the program behind each (as root it sees every user's).",
                Risk::Safe,
                &[&format!("ss -tunp dst {}", p.ip)],
                &[],
            ),
            option(
                "Where the program file is",
                "Shows the program's file and whether a package owns it.",
                Risk::Safe,
                &[&format!("ls -l {}", p.program.split(' ').next().unwrap_or(&p.program))],
                &[],
            ),
        ];
        b = b
            .confidence(level, reason)
            .subject(&fingerprint)
            .fixes(panel(osr, check, vec![], None))
            .evidence("program", p.program.clone(), None)
            .evidence("destination", format!("{}:{}/{} ({})", p.ip, p.port, p.proto, p.direction), None);
        if !is_private(&p.ip) && p.ip.parse::<std::net::IpAddr>().is_ok() {
            b = b.ioc(if p.ip.contains(':') { "ipv6" } else { "ipv4" }, &p.ip);
        }
        for f in self.findings {
            b = b.technical(&f.reason, f.data.clone());
        }
        b.technical("score", format!("{}", self.score))
            .technical("endpoint", endpoint)
            .data("connections in vigil.db (last 24 h)")
            .when(self.first_raised)
            .attack_ids(&self.attack())
            .make()
    }
}

// ---- a scoring run over the store's connections ------------------------------------------

/// One stored connection, as the scorer reads it.
#[derive(Debug, Clone)]
pub struct Row {
    pub id: i64,
    pub program: String,
    pub ip: String,
    pub direction: String,
    pub proto: String,
    pub local_port: u32,
    pub remote_port: u32,
    pub first_seen: f64,
    pub last_seen: f64,
}

/// A scored pair, and the allowlist rule that covers it, if any.
pub struct PairScore {
    pub pair: Pair,
    pub score: f64,
    pub findings: Vec<Scored>,
    pub rule: Option<Rule>,
}

/// Group rows into pairs and score each. A connection not seen in the last two looks is
/// closed at its last sighting.
pub fn run(rows: &[Row], cx: &Context, rules: &[Rule]) -> Vec<PairScore> {
    let mut pairs: std::collections::BTreeMap<(String, String, u32, String, String), Vec<Conn>> = Default::default();
    for r in rows {
        let port = if r.direction == "in" { r.local_port } else { r.remote_port };
        let open = cx.now - r.last_seen <= 2.5 * cx.poll;
        pairs.entry((r.program.clone(), r.ip.clone(), port, r.proto.clone(), r.direction.clone())).or_default().push(
            Conn {
                id: r.id,
                opened_at: r.first_seen,
                closed_at: (!open).then_some(r.last_seen),
                bytes_sent: None,
                bytes_recv: None,
                local_port: r.local_port,
            },
        );
    }
    pairs
        .into_iter()
        .map(|((program, ip, port, proto, direction), mut conns)| {
            conns.sort_by(|a, b| a.opened_at.partial_cmp(&b.opened_at).unwrap_or(std::cmp::Ordering::Equal));
            let (pair, score, findings) = score_pair((&program, &ip, port, &proto, &direction), &conns, cx);
            let rule = first_match(rules, &pair).cloned();
            PairScore { pair, score, findings, rule }
        })
        .collect()
}

/// The pairs that alert: at or above the threshold, not allowlisted, one per program,
/// address and direction (the highest-scoring port).
pub fn alerts(results: &[PairScore]) -> Vec<&PairScore> {
    let mut best: std::collections::BTreeMap<String, &PairScore> = Default::default();
    for r in results.iter().filter(|r| r.score >= ALERT_THRESHOLD && r.rule.is_none()) {
        let k = format!("{}|{}|{}", r.pair.program, r.pair.ip, r.pair.direction);
        if best.get(&k).is_none_or(|b| r.score > b.score) {
            best.insert(k, r);
        }
    }
    best.into_values().collect()
}
