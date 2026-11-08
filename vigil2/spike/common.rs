//! Shared, SYNTHETIC data and measurement for the toolkit spike (docs/RUST_REWRITE.md 5.1).
//! Included by both spike binaries with `#[path = "../../common.rs"]`, so the two
//! toolkits draw exactly the same scene and report the same numbers.

#![allow(dead_code)]

use std::time::{Duration, Instant};

/// A deterministic pseudo-random sequence (no `rand` crate in the spike).
pub struct Lcg(u64);

impl Lcg {
    pub fn new(seed: u64) -> Self {
        Lcg(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    pub fn f(&mut self) -> f32 {
        (self.next() % 1_000_000) as f32 / 1_000_000.0
    }
}

#[derive(Clone)]
pub struct Node {
    pub x: f32,
    pub y: f32,
    pub program: bool,
    pub label: String,
}

#[derive(Clone)]
pub struct Edge {
    pub a: usize,
    pub b: usize,
    pub speed: f32,
    pub phase: f32,
}

#[derive(Clone)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

pub const PROGRAMS: usize = 200;
pub const NODES: usize = 2000;

/// 200 programs in a cluster, 1,800 destinations in rings, ~2,400 live connections.
pub fn graph() -> Graph {
    let mut r = Lcg::new(7);
    let mut nodes = Vec::with_capacity(NODES);
    for i in 0..NODES {
        if i < PROGRAMS {
            let a = r.f() * std::f32::consts::TAU;
            let d = 60.0 + r.f() * 180.0;
            nodes.push(Node { x: a.cos() * d, y: a.sin() * d, program: true, label: format!("program-{i}") });
        } else {
            let a = r.f() * std::f32::consts::TAU;
            let d = 420.0 + r.f() * 520.0;
            nodes.push(Node { x: a.cos() * d, y: a.sin() * d, program: false, label: format!("198.51.100.{}", i % 250) });
        }
    }
    let mut edges = Vec::new();
    for b in PROGRAMS..NODES {
        let n = 1 + (r.next() % 2) as usize;
        for _ in 0..n {
            edges.push(Edge { a: (r.next() as usize) % PROGRAMS, b, speed: 0.2 + r.f() * 0.6, phase: r.f() });
        }
    }
    edges.truncate(2400);
    Graph { nodes, edges }
}

#[derive(Clone)]
pub struct Row {
    pub pid: u32,
    pub name: String,
    pub user: &'static str,
    pub cpu: f32,
    pub rss_mb: f32,
    pub cmd: String,
    /// name + cmd in lower case, for type-ahead filtering.
    pub hay: String,
}

const NAMES: [&str; 16] = [
    "firefox", "sshd", "systemd", "pipewire", "code", "syncthing", "kworker/3:1", "python3", "bash", "zsh",
    "NetworkManager", "chronyd", "gnome-shell", "Xwayland", "steam", "dbus-broker",
];

/// 100,000 synthetic process rows.
pub fn rows(n: usize) -> Vec<Row> {
    let mut r = Lcg::new(11);
    (0..n)
        .map(|i| {
            let name = NAMES[(r.next() as usize) % NAMES.len()].to_string();
            let cmd = format!("/usr/bin/{name} --instance {i} --profile p{}", r.next() % 97);
            Row {
                pid: 1000 + i as u32,
                hay: format!("{} {}", name.to_lowercase(), cmd.to_lowercase()),
                name,
                user: if r.next() % 3 == 0 { "root" } else { "ula" },
                cpu: r.f() * 12.0,
                rss_mb: r.f() * 900.0,
                cmd,
            }
        })
        .collect()
}

pub fn filter(rows: &[Row], query: &str) -> Vec<usize> {
    let q = query.to_lowercase();
    if q.is_empty() {
        return (0..rows.len()).collect();
    }
    rows.iter().enumerate().filter(|(_, r)| r.hay.contains(&q)).map(|(i, _)| i).collect()
}

/// What the bench types into the palette, one step every few frames.
pub const TYPING: [&str; 14] =
    ["f", "fi", "fir", "fire", "firef", "firefo", "firefox", "", "s", "ss", "ssh", "sshd", "sshd 4", ""];

pub fn screen() -> String {
    std::env::var("SPIKE_SCREEN").unwrap_or_else(|_| "map".into())
}

pub fn bench_seconds() -> Option<f64> {
    std::env::var("SPIKE_SECONDS").ok().and_then(|s| s.parse().ok())
}

pub fn rss_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).map(|l| l.to_string()))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|k| k.parse::<f64>().ok()))
        .map_or(0.0, |kb| kb / 1024.0)
}

/// CPU time this process has used (user + system, all threads), in milliseconds.
pub fn cpu_ms() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rest = stat.rsplit_once(')').map_or("", |(_, r)| r);
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ticks: f64 = f.get(11).and_then(|u| u.parse().ok()).unwrap_or(0.0) + f.get(12).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    ticks * 10.0 // USER_HZ is 100 on Linux
}

/// `SPIKE_IDLE=N`: sit still for N seconds and report how much CPU the idle app used.
pub fn spawn_idle_probe(toolkit: &'static str) {
    let Some(secs) = std::env::var("SPIKE_IDLE").ok().and_then(|s| s.parse::<f64>().ok()) else { return };
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        let (c0, t0) = (cpu_ms(), Instant::now());
        std::thread::sleep(Duration::from_secs_f64(secs));
        let pct = (cpu_ms() - c0) / (t0.elapsed().as_secs_f64() * 1000.0) * 100.0;
        println!("{{\"toolkit\": \"{toolkit}\", \"screen\": \"{}\", \"idle_cpu_percent\": {pct:.2}, \"rss_mb\": {:.1}}}", screen(), rss_mb());
        std::process::exit(0);
    });
}

/// Frame timing. `frame()` is called once per rendered frame.
pub struct Stats {
    pub start: Instant,
    pub first_frame: Option<Duration>,
    pub last: Option<Instant>,
    pub intervals: Vec<f64>,
    pub filter_ms: Vec<f64>,
    pub frames: u64,
    pub cpu_at_1s: Option<(f64, u64)>,
}

impl Stats {
    pub fn new(start: Instant) -> Self {
        Stats { start, first_frame: None, last: None, intervals: vec![], filter_ms: vec![], frames: 0, cpu_at_1s: None }
    }
    pub fn frame(&mut self) {
        let now = Instant::now();
        if self.first_frame.is_none() {
            self.first_frame = Some(now - self.start);
        }
        if let Some(l) = self.last {
            // Skip the first second: shader compilation and font loading.
            if now - self.start > Duration::from_secs(1) {
                if self.cpu_at_1s.is_none() {
                    self.cpu_at_1s = Some((cpu_ms(), self.frames));
                }
                self.intervals.push((now - l).as_secs_f64() * 1000.0);
            }
        }
        self.last = Some(now);
        self.frames += 1;
    }
    pub fn done(&self) -> bool {
        bench_seconds().is_some_and(|s| self.start.elapsed().as_secs_f64() > s)
    }
    fn pct(v: &[f64], p: f64) -> f64 {
        if v.is_empty() {
            return 0.0;
        }
        let mut s = v.to_vec();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        s[((s.len() - 1) as f64 * p).round() as usize]
    }
    pub fn report(&self, toolkit: &str) -> String {
        let n = self.intervals.len().max(1) as f64;
        let mean = self.intervals.iter().sum::<f64>() / n;
        format!(
            "{{\"toolkit\": \"{toolkit}\", \"screen\": \"{}\", \"first_frame_ms\": {:.1}, \"frames\": {}, \
             \"frame_ms_mean\": {:.2}, \"frame_ms_p50\": {:.2}, \"frame_ms_p95\": {:.2}, \"frame_ms_p99\": {:.2}, \
             \"fps\": {:.1}, \"cpu_ms_per_frame\": {:.2}, \"filter_ms_mean\": {:.2}, \"filter_ms_max\": {:.2}, \"rss_mb\": {:.1}}}",
            screen(),
            self.first_frame.map_or(0.0, |d| d.as_secs_f64() * 1000.0),
            self.frames,
            mean,
            Self::pct(&self.intervals, 0.5),
            Self::pct(&self.intervals, 0.95),
            Self::pct(&self.intervals, 0.99),
            1000.0 / mean,
            self.cpu_at_1s.map_or(0.0, |(c, f)| (cpu_ms() - c) / (self.frames - f).max(1) as f64),
            self.filter_ms.iter().sum::<f64>() / self.filter_ms.len().max(1) as f64,
            self.filter_ms.iter().cloned().fold(0.0, f64::max),
            rss_mb(),
        )
    }
}
