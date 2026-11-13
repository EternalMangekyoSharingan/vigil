//! The areas, fed by the daemon's last look.
//!
//! Home (overview, first sightings), Network (live map, connections, time machine),
//! Processes (tree, table), Cases (the event log) show real data. Areas whose engines
//! arrive in later milestones say so, and say what works today; none shows made-up data.

use gpui::{div, prelude::*, px, AnyElement, ClickEvent, Context};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use vigil_model::host::{ProcessInfo, Socket};
use vigil_model::netaddr::scope_of;
use vigil_model::wording;
use vigil_ui_core::areas::AREAS;
use vigil_ui_core::motion;
use vigil_ui_core::settings::View;
use vigil_ui_core::theme::Rgba;

use crate::ui::{ago, button, c, ca, card, card_title, chip, enter, id, id2, kbd, row_enter};
use crate::{live::Snapshot, Conn, ProcSort, Sel, Vigil, DETAIL_W};

/// "Firefox" for well-known programs, else the collector's name ("http.server (python3)").
pub fn display_name(p: Option<&ProcessInfo>, key: &str) -> String {
    let exe = p.and_then(|p| p.exe.as_deref()).unwrap_or(key.split(' ').next().unwrap_or(key));
    let base = exe.rsplit('/').next().unwrap_or(exe).trim_end_matches(" (deleted)").to_lowercase();
    match wording::FRIENDLY.iter().find(|(k, _)| *k == base) {
        Some((_, v)) => v.to_string(),
        None => p.map_or_else(|| wording::friendly_program(None, Some(key), None), |p| p.name.clone()),
    }
}

pub fn program_name(d: &Snapshot, key: &str) -> String {
    program_name_in(&d.net, key)
}

pub fn program_name_in(net: &vigil_model::host::NetSnapshot, key: &str) -> String {
    let p = net
        .sockets
        .iter()
        .find(|s| s.program.as_deref() == Some(key))
        .and_then(|s| s.pid)
        .and_then(|pid| net.processes.get(&pid));
    wording::printable(&display_name(p, key))
}

fn endpoint(ip: &str, port: u32) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// Outbound and inbound connections that leave this machine, the ones people care about.
pub fn real_connections(d: &Snapshot) -> impl Iterator<Item = &Socket> {
    real_connections_in(&d.net)
}

pub fn real_connections_in(net: &vigil_model::host::NetSnapshot) -> impl Iterator<Item = &Socket> {
    net.sockets.iter().filter(|s| s.kind == "connection" && scope_of(&s.remote_ip) != "loopback")
}

/// Processes in tree order: (pid, depth).
pub fn tree_order(procs: &[ProcessInfo]) -> Vec<(u32, usize)> {
    let pids: BTreeSet<u32> = procs.iter().map(|p| p.pid).collect();
    let mut kids: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut roots = vec![];
    for p in procs {
        if p.ppid != 0 && pids.contains(&p.ppid) && p.ppid != p.pid {
            kids.entry(p.ppid).or_default().push(p.pid);
        } else {
            roots.push(p.pid);
        }
    }
    // Siblings in pid order (roughly the order they started), the same on every refresh.
    for ch in kids.values_mut() {
        ch.sort_unstable();
    }
    roots.sort_unstable();
    let mut out = vec![];
    let mut stack: Vec<(u32, usize)> = roots.into_iter().rev().map(|r| (r, 0)).collect();
    let mut seen = BTreeSet::new();
    while let Some((pid, depth)) = stack.pop() {
        if !seen.insert(pid) {
            continue;
        }
        out.push((pid, depth));
        if let Some(ch) = kids.get(&pid) {
            for k in ch.iter().rev() {
                stack.push((*k, depth + 1));
            }
        }
    }
    out
}

fn matches_filter(p: &ProcessInfo, f: &str) -> bool {
    f.is_empty()
        || format!("{} {} {} {}", p.name, p.user, p.pid, p.cmdline.join(" ")).to_lowercase().contains(&f.to_lowercase())
}

fn socket_matches(s: &Socket, d: &Snapshot, f: &str) -> bool {
    if f.is_empty() {
        return true;
    }
    if let Some(pid) = f.strip_prefix("pid:") {
        return s.pids.iter().any(|p| p.to_string() == pid);
    }
    let name = s.program.as_deref().map(|k| program_name(d, k)).unwrap_or_default();
    format!("{} {} {} {} {}", s.remote_ip, s.remote_port, s.state, name, s.program.as_deref().unwrap_or(""))
        .to_lowercase()
        .contains(&f.to_lowercase())
}

/// Current findings about process `pid` (subjects end in ":<pid>"), worst first.
pub fn proc_findings(d: &Snapshot, pid: u32) -> Vec<&vigil_model::finding::Finding> {
    let tail = format!(":{pid}");
    let mut v: Vec<_> = d.findings.iter().filter(|f| f.tool == "tasks" && f.subject.ends_with(&tail)).collect();
    v.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    v
}

/// Current network alerts about program `key` (their evidence names the program), worst first.
pub fn program_findings<'a>(d: &'a Snapshot, key: &str) -> Vec<&'a vigil_model::finding::Finding> {
    let mut v: Vec<_> = d
        .findings
        .iter()
        .filter(|f| f.tool == "net" && f.evidence.iter().any(|e| e.kind == "program" && e.value.as_str() == Some(key)))
        .collect();
    v.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
    v
}

/// The colour for a severity.
pub fn sev_colour(t: &vigil_ui_core::theme::Theme, s: vigil_model::finding::Severity) -> Rgba {
    use vigil_model::finding::Severity;
    match s {
        Severity::High => t.danger,
        Severity::Medium => t.warn,
        Severity::Low => t.live,
        Severity::Info => t.text[2],
    }
}

/// One program's processes: (count, CPU %, memory kB, executable).
type ProgUse = (usize, f32, u64, String);

/// "1 alert", "3 alerts", "2 addresses".
pub fn count(n: usize, word: &str) -> String {
    match (n, word.ends_with("ss")) {
        (1, _) => format!("1 {word}"),
        (_, true) => format!("{n} {word}es"),
        _ => format!("{n} {word}s"),
    }
}

/// "689 MB", "1.6 GB".
pub fn mem(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1} GB", kb as f64 / 1024.0 / 1024.0)
    } else {
        format!("{} MB", kb / 1024)
    }
}

/// The process to show for a program: the one whose parent is not the same program (the
/// browser rather than one of its tabs), else the lowest pid.
pub fn main_pid(d: &Snapshot, key: &str) -> Option<u32> {
    let mine: BTreeSet<u32> = d.procs.processes.iter().filter(|p| p.key == key).map(|p| p.pid).collect();
    let pids: BTreeSet<u32> = if mine.is_empty() {
        d.net.sockets.iter().filter(|s| s.program.as_deref() == Some(key)).flat_map(|s| s.pids.clone()).collect()
    } else {
        mine
    };
    let parent_of = |pid: u32| d.procs.processes.iter().find(|p| p.pid == pid).map(|p| p.ppid);
    pids.iter().copied().find(|p| parent_of(*p).is_none_or(|pp| !pids.contains(&pp))).or_else(|| pids.first().copied())
}

fn hash01(s: &str) -> f32 {
    let mut h: u32 = 2166136261;
    for b in s.bytes() {
        h = (h ^ u32::from(b)).wrapping_mul(16777619);
    }
    (h % 10_000) as f32 / 10_000.0
}

/// The service usually behind a port, for people: "HTTPS", "DNS", or "port 4242".
pub fn service_name(proto: &str, port: u32) -> String {
    let name = match (proto, port) {
        (_, 443) => "HTTPS",
        (_, 80) => "HTTP",
        (_, 53) => "DNS",
        (_, 853) => "DNS over TLS",
        ("udp", 67 | 68) => "DHCP",
        ("udp", 123) => "Time (NTP)",
        (_, 22) => "SSH",
        (_, 993) => "Mail (IMAP)",
        (_, 465 | 587) => "Mail (SMTP)",
        (_, 5228) => "Google push",
        (_, 3478 | 19302..=19309) => "Calls (STUN)",
        ("udp", 51820) => "WireGuard",
        (_, 1194) => "OpenVPN",
        (_, 8080 | 8443) => "HTTP (alt)",
        (_, 22000 | 21027) => "Syncthing",
        ("udp", 5353) => "mDNS",
        ("udp", 1900) => "SSDP",
        (_, 9418) => "Git",
        (_, 6881..=6889) => "BitTorrent",
        (_, 3389) => "Remote desktop",
        (_, 5900..=5903) => "VNC",
        _ => return format!("{} {port}", proto.to_uppercase()),
    };
    name.to_string()
}

/// A connection state as an icon and a word people use.
pub fn state_view(t: &vigil_ui_core::theme::Theme, state: &str) -> gpui::Div {
    let (icon, word, colour) = match state {
        "ESTABLISHED" => ("tick", "Open", t.ok),
        "SYN_SENT" | "SYN_RECV" | "NEW_SYN_RECV" => ("clock", "Connecting", t.warn),
        "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" | "CLOSING" | "LAST_ACK" | "CLOSE_WAIT" | "CLOSE" => {
            ("clock", "Closing", t.text[2])
        }
        "LISTEN" => ("listen", "Listening", t.live),
        "UNCONN" => ("listen", "Ready (UDP)", t.live),
        other => ("activity", other, t.text[2]),
    };
    div()
        .flex()
        .items_center()
        .gap(px(5.0))
        .px(px(7.0))
        .py(px(2.0))
        .rounded(px(6.0))
        .bg(ca(colour, 0.13))
        .text_size(px(11.5))
        .text_color(c(colour))
        .child(gpui::svg().path(format!("icons/{icon}.svg")).size(px(13.0)).text_color(c(colour)))
        .child(word.to_string())
}

impl Vigil {
    /// The items j/k move through in the current view.
    pub fn list_items(&self) -> Vec<Sel> {
        let Some(d) = &self.data else { return vec![] };
        match (self.area, self.tab[self.area]) {
            (2, _) => self.process_order(d).into_iter().map(|(pid, _)| Sel::Proc(pid)).collect(),
            (1, 0) => {
                let (w, h) = self
                    .map_bounds
                    .get()
                    .map_or((1100.0, 640.0), |b| (f32::from(b.size.width), f32::from(b.size.height)));
                crate::netmap::geometry(&d.net, w, h)
                    .progs
                    .into_iter()
                    .filter(|p| !p.hidden)
                    .map(|p| Sel::Program(p.key))
                    .collect()
            }
            (1, 1) => {
                let mut seen = BTreeSet::new();
                real_connections(d)
                    .filter(|s| socket_matches(s, d, &self.filter))
                    .filter_map(|s| s.program.clone())
                    .filter(|k| seen.insert(k.clone()))
                    .map(Sel::Program)
                    .collect()
            }
            _ => vec![],
        }
    }

    pub fn area_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let reduced = self.reduced();
        // While the arrival plays, the area waits; it rises as the mark lands.
        if self.arrival.is_some() {
            return div().flex_1().into_any_element();
        }
        let page = (self.area, self.tab[self.area]);
        let main: AnyElement = match &self.data {
            None => self.no_data(cx),
            Some(_) => match page {
                (0, 0) => self.home(cx),
                (0, 1) => self.since(cx),
                (1, 0) => self.network_map(cx),
                (1, 1) => self.connections(cx),
                (1, 3) => self.time_machine_view(cx),
                (2, 0) | (2, 1) => self.processes(cx),
                (8, 0) => self.timeline(),
                _ => self.coming(cx),
            },
        };
        let pad = if self.settings.density == vigil_ui_core::settings::Density::Compact { 14.0 } else { t.pad };
        // Lists and the map keep an inspector beside them, always: selecting something fills
        // it in place, so nothing resizes and nothing is covered (owner, 2026-11-08).
        let inspected = self.data.is_some() && matches!(page, (1, 0) | (1, 1) | (2, 0) | (2, 1) | (8, 0));
        // Pages laid out to fill the window exactly; the rest scroll.
        let fills = self.data.is_some() && matches!(page, (0, 0) | (1, 0) | (1, 1) | (2, 0) | (2, 1) | (8, 0));
        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .gap(px(pad))
            .p(px(pad))
            .child(
                div()
                    .id(id("main", self.nav))
                    .flex_1()
                    .min_w(px(0.0))
                    .h_full()
                    .when(!fills, |el| el.overflow_y_scroll())
                    .child(enter(
                        div().flex().flex_col().gap(px(16.0)).when(fills, |el| el.h_full()).child(main),
                        id("area", self.nav),
                        0.0,
                        motion::AREA_RISE_PX,
                        reduced,
                    )),
            )
            .when(inspected, |d| d.child(div().w(px(DETAIL_W)).flex_none().h_full().child(self.inspector(cx))))
            .into_any_element()
    }

    fn no_data(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let (title, body) = match &self.conn {
            Conn::Looking | Conn::Connected(_) => ("Looking for the Vigil daemon…".to_string(), "This takes a moment.".to_string()),
            Conn::Failed(e) => (
                e.clone(),
                "Vigil's app shows what the daemon sees. Start the daemon, and this page fills in by itself within a few seconds.".to_string(),
            ),
        };
        let dev = "cargo run --release -p vigild -- --bus session";
        let sys = "sudo systemctl enable --now vigild";
        let line = |label: &'static str, cmd: &'static str, n: u64, cx: &mut Context<Self>| {
            div()
                .flex()
                .items_center()
                .gap(px(12.0))
                .py(px(10.0))
                .border_t_1()
                .border_color(c(t.line[0]))
                .child(div().w(px(150.0)).text_color(c(t.text[2])).text_size(px(12.0)).child(label))
                .child(div().flex_1().font_family(t.mono_fonts[0]).text_color(c(t.text[0])).child(cmd))
                .child(button(t, id("copy-cmd", n), "Copy", false).on_click(cx.listener(
                    move |this, _: &ClickEvent, _w, cx| {
                        this.copy(cmd.to_string(), "the command", cx);
                        cx.notify();
                    },
                )))
        };
        card(t)
            .p(px(t.pad))
            .gap(px(8.0))
            .max_w(px(820.0))
            .child(div().text_size(px(18.0)).child(title))
            .child(div().text_color(c(t.text[1])).pb(px(8.0)).child(body))
            .child(line("While developing", dev, 1, cx))
            .child(line("Installed package", sys, 2, cx))
            .into_any_element()
    }

    fn since(&self, _cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        let day = vigil_model::finding::now() - 86400.0;
        let firsts: Vec<_> = d.events.iter().filter(|e| e.kind == "first-seen" && e.ts > day).collect();
        let mut rows = vec![];
        for (i, e) in firsts.iter().enumerate() {
            let prog = e.detail.get("program").and_then(|v| v.as_str()).unwrap_or("");
            rows.push(row_enter(
                div()
                    .py(px(9.0))
                    .flex()
                    .gap(px(14.0))
                    .border_t_1()
                    .border_color(c(t.line[0]))
                    .child(div().w(px(90.0)).text_color(c(t.text[2])).child(ago(e.ts)))
                    .child(
                        div().flex_1().child(format!(
                            "First time on the network: {}",
                            wording::printable(&display_name(None, prog))
                        )),
                    )
                    .child(
                        div()
                            .text_color(c(t.text[2]))
                            .text_size(px(11.5))
                            .truncate()
                            .max_w(px(380.0))
                            .child(wording::printable(prog)),
                    ),
                id2("since", self.nav, i as u64),
                i,
                self.reduced(),
            ));
        }
        card(t)
            .p(px(16.0))
            .child(card_title(t, "New in the last 24 hours"))
            .children(rows)
            .when(firsts.is_empty(), |el| {
                el.child(
                    div()
                        .pt(px(8.0))
                        .text_color(c(t.text[2]))
                        .child("Nothing new: every program using the network was seen before."),
                )
            })
            .into_any_element()
    }

    fn filter_box(&self, placeholder: &str, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let focused = self.filter_focus;
        div()
            .id("filter")
            .h(px(34.0))
            .px(px(12.0))
            .flex()
            .items_center()
            .gap(px(10.0))
            .rounded(px(t.radius_sm))
            .bg(c(t.bg[2]))
            .border_1()
            .border_color(if focused { c(t.accent) } else { c(t.line[1]) })
            .cursor_text()
            .child(gpui::svg().path("icons/search.svg").size(px(15.0)).text_color(c(t.text[2])))
            .child(if self.filter.is_empty() && !focused {
                div().text_color(c(t.text[2])).child(placeholder.to_string())
            } else {
                div().child(format!("{}{}", self.filter, if focused { "▏" } else { "" }))
            })
            .child(div().flex_1())
            .child(kbd(t, "/"))
            .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                this.filter_focus = true;
                cx.notify();
            }))
            .into_any_element()
    }

    fn connections(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        let expert = self.settings.view(AREAS[1].id) == View::Expert;
        let reduced = self.reduced();
        let socks: Vec<&Socket> = real_connections(d).filter(|s| socket_matches(s, d, &self.filter)).collect();
        let head = |cols: &[(&str, f32)]| {
            div().flex().px(px(10.0)).pb(px(6.0)).text_size(px(11.5)).text_color(c(t.text[2])).children(
                cols.iter().map(|(n, w)| {
                    if *w > 0.0 {
                        div().w(px(*w)).child(n.to_string())
                    } else {
                        div().flex_1().child(n.to_string())
                    }
                }),
            )
        };
        let mut cols =
            vec![("Program", 0.0), ("Address", 250.0), ("Service", 120.0), ("Where", 100.0), ("State", 130.0)];
        if expert {
            cols.extend([("Local", 230.0), ("uid", 60.0), ("inode", 90.0)]);
        }
        let mut rows = vec![];
        for (i, s) in socks.iter().enumerate() {
            let selected = matches!(&self.sel, Some(Sel::Program(k)) if s.program.as_ref() == Some(k));
            let name = match (&s.program, &s.hidden) {
                (Some(k), _) => program_name(d, k),
                (None, Some(h)) => h.label.clone(),
                _ => "-".into(),
            };
            let key = s.program.clone();
            let service = service_name(&s.proto, if s.direction == "in" { s.local_port } else { s.remote_port });
            let where_ = match scope_of(&s.remote_ip) {
                "internet" => "Internet",
                "lan" => "Local network",
                "link-local" => "This link",
                "loopback" => "This PC",
                other => other,
            };
            let mut row = div()
                .id(id2("conn", self.nav, i as u64))
                .h(px(34.0))
                .px(px(10.0))
                .flex()
                .items_center()
                .rounded(px(t.radius_sm))
                .cursor_pointer()
                .bg(if selected { c(t.accent_soft) } else { ca(t.bg[0], 0.0) })
                .hover(|st| st.bg(ca(Rgba(0xffffff0a), 1.0)))
                .child(
                    div()
                        .flex_1()
                        .flex()
                        .items_center()
                        .gap(px(8.0))
                        .child(
                            gpui::svg()
                                .path(if s.direction == "in" { "icons/in.svg" } else { "icons/out.svg" })
                                .size(px(14.0))
                                .text_color(if s.direction == "in" { c(t.warn) } else { c(t.text[2]) }),
                        )
                        .child(match &s.program {
                            Some(k) => self.app_icon(k, 18.0),
                            None => div().size(px(18.0)).into_any_element(),
                        })
                        .child(
                            div()
                                .truncate()
                                .text_color(if s.program.is_some() { c(t.text[0]) } else { c(t.text[2]) })
                                .child(name),
                        ),
                )
                .child(div().w(px(250.0)).truncate().child(endpoint(&s.remote_ip, s.remote_port)))
                .child(div().w(px(120.0)).truncate().text_color(c(t.text[1])).child(service))
                .child(div().w(px(100.0)).text_color(c(t.text[2])).child(where_))
                .child(div().w(px(130.0)).flex().child(state_view(t, &s.state)));
            if expert {
                row = row
                    .child(
                        div()
                            .w(px(230.0))
                            .truncate()
                            .text_color(c(t.text[2]))
                            .child(endpoint(&s.local_ip, s.local_port)),
                    )
                    .child(div().w(px(60.0)).text_color(c(t.text[2])).child(s.uid.to_string()))
                    .child(div().w(px(90.0)).text_color(c(t.text[2])).child(s.inode.to_string()));
            }
            let row = row.on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                let next = key.clone().map(Sel::Program);
                this.sel = if this.sel == next { None } else { next };
                cx.notify();
            }));
            rows.push(row_enter(row, id2("conn-in", self.nav, i as u64), i, reduced).into_any_element());
        }
        let n = socks.len();
        div()
            .size_full()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.0))
                    .child(div().w(px(420.0)).child(self.filter_box("Filter by program, address, port or state", cx)))
                    .child(div().text_color(c(t.text[2])).child(format!("{n} connections"))),
            )
            .child(
                card(t).flex_1().min_h(px(0.0)).p(px(10.0)).child(head(&cols)).child(
                    div()
                        .id(id("conn-rows", self.nav))
                        .flex_1()
                        .min_h(px(0.0))
                        .overflow_y_scroll()
                        .children(rows)
                        .when(n == 0, |el| {
                            el.child(div().p(px(12.0)).text_color(c(t.text[2])).child("No connection matches."))
                        }),
                ),
            )
            .into_any_element()
    }

    fn time_machine_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let now = vigil_model::finding::now();
        let mut buttons = vec![];
        for (i, (label, secs)) in [
            ("5 minutes ago", 300.0),
            ("1 hour ago", 3600.0),
            ("6 hours ago", 21600.0),
            ("Yesterday", 86400.0),
            ("A week ago", 604800.0),
        ]
        .into_iter()
        .enumerate()
        {
            let chosen = self.at_asked.is_some_and(|a| ((now - a) - secs).abs() < 120.0);
            buttons.push(button(t, id("tm", i as u64), label, chosen).on_click(cx.listener(
                move |this, _: &ClickEvent, _w, cx| {
                    this.time_machine(vigil_model::finding::now() - secs);
                    cx.notify();
                },
            )));
        }
        let body: AnyElement = match (&self.at, self.at_asked) {
            (_, None) => div()
                .text_color(c(t.text[2]))
                .child("Pick a moment. Vigil shows what was talking then, from its history.")
                .into_any_element(),
            (Some((when, rows)), Some(asked)) if (*when - asked).abs() < 0.5 => {
                let mut list = vec![];
                for (i, r) in rows.iter().enumerate() {
                    let name = r
                        .program
                        .as_deref()
                        .map_or("(not attributed)".to_string(), |k| wording::printable(&display_name(None, k)));
                    list.push(row_enter(
                        div()
                            .h(px(32.0))
                            .px(px(10.0))
                            .flex()
                            .items_center()
                            .border_t_1()
                            .border_color(c(t.line[0]))
                            .child(div().flex_1().truncate().child(name))
                            .child(div().w(px(280.0)).child(endpoint(&r.remote_ip, r.remote_port)))
                            .child(div().w(px(240.0)).text_color(c(t.text[2])).child(format!(
                                "open {} → {}",
                                self.clock(r.first_seen),
                                self.clock(r.last_seen)
                            ))),
                        id2("tmrow", self.nav + self.updates, i as u64),
                        i,
                        self.reduced(),
                    ));
                }
                card(t)
                    .p(px(12.0))
                    .child(card_title(t, format!("Open around {}: {} connections", self.clock(*when), rows.len())))
                    .children(list)
                    .when(rows.is_empty(), |el| el.child(div().pt(px(8.0)).text_color(c(t.text[2])).child("Nothing recorded then. History starts when the daemon first ran, and polling misses connections shorter than two seconds.")))
                    .into_any_element()
            }
            _ => div().text_color(c(t.text[2])).child("Looking back…").into_any_element(),
        };
        div()
            .flex()
            .flex_col()
            .gap(px(14.0))
            .child(div().flex().gap(px(8.0)).children(buttons))
            .child(body)
            .into_any_element()
    }

    /// "14:05", or "Nov 7, 14:05" for another day, in local time.
    pub fn clock(&self, ts: f64) -> String {
        let local = ts as i64 + self.utc_offset_s;
        let now_local = vigil_model::finding::now() as i64 + self.utc_offset_s;
        let (h, m) = ((local.rem_euclid(86400)) / 3600, (local.rem_euclid(3600)) / 60);
        let days_ago = now_local.div_euclid(86400) - local.div_euclid(86400);
        match days_ago {
            0 => format!("{h:02}:{m:02}"),
            1 => format!("yesterday {h:02}:{m:02}"),
            n => format!("{n} days ago {h:02}:{m:02}"),
        }
    }

    /// The rows of the process list in the order shown: (pid, depth).
    fn process_order(&self, d: &Snapshot) -> Vec<(u32, usize)> {
        let tree = self.tab[2] == 0;
        let by_pid: HashMap<u32, &ProcessInfo> = d.procs.processes.iter().map(|p| (p.pid, p)).collect();
        let keep = |pid: &u32| by_pid.get(pid).is_some_and(|p| matches_filter(p, &self.filter));
        if tree {
            return tree_order(&d.procs.processes).into_iter().filter(|(pid, _)| keep(pid)).collect();
        }
        let mut v: Vec<&ProcessInfo> = d.procs.processes.iter().filter(|p| keep(&p.pid)).collect();
        let (sort, desc) = self.proc_sort;
        let cpu = |p: &ProcessInfo| p.cpu_pct.unwrap_or(0.0);
        v.sort_by(|a, b| {
            let o = match sort {
                ProcSort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                ProcSort::User => a.user.cmp(&b.user),
                ProcSort::Cpu => cpu(a).partial_cmp(&cpu(b)).unwrap_or(std::cmp::Ordering::Equal),
                ProcSort::Memory => a.rss_kb.cmp(&b.rss_kb),
                ProcSort::Started => a.started.partial_cmp(&b.started).unwrap_or(std::cmp::Ordering::Equal),
                ProcSort::Pid | ProcSort::Tree => a.pid.cmp(&b.pid),
            };
            let o = o.then(a.pid.cmp(&b.pid));
            if desc {
                o.reverse()
            } else {
                o
            }
        });
        v.into_iter().map(|p| (p.pid, 0)).collect()
    }

    fn processes(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        let tree = self.tab[2] == 0;
        let order = self.process_order(d);
        let n = order.len();
        // A jump (from the map, Home, the palette or j/k) brings the selection into view.
        if let (Some(how), Some(Sel::Proc(pid))) = (self.reveal.take(), &self.sel) {
            if let Some(ix) = order.iter().position(|(p, _)| p == pid) {
                self.list_scroll.scroll_to_item(ix, how);
            }
        }
        *self.rows.borrow_mut() = order;
        let hidden: usize = d.procs.unreadable_by_uid.values().sum();
        let note = if hidden > 0 {
            format!("{n} processes · details of {hidden} are limited (other users or protected)")
        } else {
            format!("{n} processes")
        };
        let head_cell = |label: &'static str, sort: ProcSort, w: Option<f32>, right: bool, cx: &mut Context<Self>| {
            let (cur, desc) = self.proc_sort;
            let on = !tree && cur == sort;
            let arrow = if on {
                if desc {
                    " ↓"
                } else {
                    " ↑"
                }
            } else {
                ""
            };
            let cell = div()
                .id(label)
                .flex()
                .when(right, |el| el.justify_end())
                .when(!tree, |el| el.cursor_pointer().hover(|s| s.text_color(c(t.text[0]))))
                .text_color(if on { c(t.text[0]) } else { c(t.text[2]) })
                .child(format!("{label}{arrow}"))
                .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                    if this.tab[2] == 0 {
                        return;
                    }
                    // Numbers sort biggest first; words A to Z. A second click flips it.
                    let first_desc = matches!(sort, ProcSort::Cpu | ProcSort::Memory | ProcSort::Started);
                    this.proc_sort =
                        if this.proc_sort.0 == sort { (sort, !this.proc_sort.1) } else { (sort, first_desc) };
                    this.reveal.set(Some(gpui::ScrollStrategy::Nearest));
                    cx.notify();
                }));
            match w {
                Some(w) => cell.w(px(w)).flex_none(),
                None => cell.flex_1().min_w(px(0.0)),
            }
        };
        let head = div()
            .flex()
            .h(px(30.0))
            .items_center()
            .px(px(12.0))
            .gap(px(12.0))
            .border_b_1()
            .border_color(c(t.line[0]))
            .text_size(px(11.5))
            .child(head_cell("Program", ProcSort::Name, None, false, cx))
            .child(head_cell("PID", ProcSort::Pid, Some(64.0), true, cx))
            .child(head_cell("User", ProcSort::User, Some(96.0), false, cx))
            .child(head_cell("CPU", ProcSort::Cpu, Some(56.0), true, cx))
            .child(head_cell("Memory", ProcSort::Memory, Some(76.0), true, cx))
            .child(head_cell("Started", ProcSort::Started, Some(96.0), false, cx));
        let list = gpui::uniform_list(
            id("proc-list", self.tab[2] as u64),
            n,
            cx.processor(|this: &mut Vigil, range: std::ops::Range<usize>, _w, cx| this.process_rows(range, cx)),
        )
        .track_scroll(&self.list_scroll)
        .flex_1()
        .min_h(px(0.0));
        div()
            .size_full()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(14.0))
                    .child(div().w(px(420.0)).child(self.filter_box("Filter by name, user, pid or command line", cx)))
                    .child(div().text_color(c(t.text[2])).text_size(px(12.0)).child(note))
                    .child(div().flex_1())
                    .child(div().text_size(px(11.5)).text_color(c(t.text[2])).child(if tree {
                        "Tree: children under the program that started them"
                    } else {
                        "Click a column to sort"
                    })),
            )
            .child(card(t).flex_1().min_h(px(0.0)).overflow_hidden().child(head).child(list).when(n == 0, |el| {
                el.child(div().p(px(16.0)).text_color(c(t.text[2])).child("No process matches the filter."))
            }))
            .into_any_element()
    }

    /// The process rows `range` of the virtual list (only the visible ones are built).
    fn process_rows(&mut self, range: std::ops::Range<usize>, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let t = self.theme.clone();
        let Some(d) = &self.data else { return vec![] };
        let tree = self.tab[2] == 0;
        let rows = self.rows.borrow();
        let by_pid: HashMap<u32, &ProcessInfo> = d.procs.processes.iter().map(|p| (p.pid, p)).collect();
        let net: HashMap<u32, usize> =
            d.net.sockets.iter().filter(|s| s.kind == "connection").flat_map(|s| s.pids.clone()).fold(
                HashMap::new(),
                |mut m, p| {
                    *m.entry(p).or_insert(0) += 1;
                    m
                },
            );
        let mut out = vec![];
        for ix in range {
            let Some(&(pid, depth)) = rows.get(ix) else { continue };
            let Some(p) = by_pid.get(&pid) else { continue };
            let selected = self.sel == Some(Sel::Proc(pid));
            let indent = if tree && self.filter.is_empty() { depth.min(14) as f32 * 14.0 } else { 0.0 };
            let args = wording::printable(&p.cmdline.iter().skip(1).cloned().collect::<Vec<_>>().join(" "));
            let conns = net.get(&pid).copied().unwrap_or(0);
            let flagged = proc_findings(d, pid);
            let cpu = p.cpu_pct.unwrap_or(0.0);
            let dim = |s: String| div().text_color(c(t.text[2])).child(s);
            let row = div()
                .id(("proc", pid as u64))
                .w_full()
                .h(px(30.0))
                .px(px(11.0))
                .flex()
                .items_center()
                .gap(px(12.0))
                .rounded(px(t.radius_sm))
                .border_1()
                .cursor_pointer()
                .when(selected, |el| el.bg(c(t.accent_soft)).border_color(c(t.accent)))
                .when(!selected, |el| el.border_color(ca(t.bg[0], 0.0)).hover(|st| st.bg(ca(Rgba(0xffffff0a), 1.0))))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.0))
                        .flex()
                        .items_center()
                        .gap(px(8.0))
                        .pl(px(indent))
                        .when(indent > 0.0, |el| el.child(div().w(px(7.0)).h(px(1.0)).flex_none().bg(c(t.line[2]))))
                        .child(match &p.exe {
                            Some(e) => self.app_icon(e, 16.0),
                            None => div().size(px(16.0)).flex_none().into_any_element(),
                        })
                        .child(div().flex_none().max_w(px(260.0)).truncate().child(wording::printable(&p.name)))
                        .when_some(flagged.first(), |el, f| {
                            let more =
                                if flagged.len() > 1 { format!(" +{}", flagged.len() - 1) } else { String::new() };
                            el.child(chip(format!("{}{more}", f.severity.as_str()), sev_colour(&t, f.severity)))
                        })
                        .when(p.exe_deleted && flagged.is_empty(), |el| el.child(chip("deleted file", t.warn)))
                        .when(conns > 0, |el| el.child(chip(format!("{conns} net"), t.live)))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.0))
                                .truncate()
                                .text_size(px(12.0))
                                .text_color(c(t.text[2]))
                                .child(args),
                        ),
                )
                .child(dim(p.pid.to_string()).w(px(64.0)).flex_none().flex().justify_end())
                .child(div().w(px(96.0)).flex_none().truncate().text_color(c(t.text[1])).child(p.user.clone()))
                .child(
                    div()
                        .w(px(56.0))
                        .flex_none()
                        .flex()
                        .justify_end()
                        .text_color(if cpu >= 10.0 {
                            c(t.accent)
                        } else if cpu >= 0.1 {
                            c(t.text[1])
                        } else {
                            c(t.text[2])
                        })
                        .child(if p.cpu_pct.is_some() { format!("{cpu:.1}%") } else { "-".into() }),
                )
                .child(dim(p.rss_kb.map_or("-".into(), mem)).w(px(76.0)).flex_none().flex().justify_end())
                .child(dim(p.started.map_or("-".into(), ago)).w(px(96.0)).flex_none().truncate())
                .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                    this.sel = if this.sel == Some(Sel::Proc(pid)) { None } else { Some(Sel::Proc(pid)) };
                    cx.notify();
                }));
            out.push(row.into_any_element());
        }
        out
    }

    fn timeline(&self) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        let mut rows = vec![];
        let mut last_day = String::new();
        for (i, e) in d.events.iter().enumerate().take(300) {
            let clock = self.clock(e.ts);
            let day = clock.rsplit_once(' ').map_or("Today".to_string(), |(d, _)| d.to_string());
            if day != last_day {
                rows.push(
                    div()
                        .pt(px(14.0))
                        .pb(px(4.0))
                        .text_size(px(12.0))
                        .text_color(c(t.text[2]))
                        .child(if day.contains(':') { "Today".to_string() } else { day.clone() })
                        .into_any_element(),
                );
                last_day = day;
            }
            let colour = match e.kind.as_str() {
                "first-seen" => t.live,
                "daemon" => t.text[2],
                _ => t.accent,
            };
            rows.push(
                row_enter(
                    div()
                        .py(px(8.0))
                        .flex()
                        .gap(px(14.0))
                        .items_center()
                        .border_t_1()
                        .border_color(c(t.line[0]))
                        .child(
                            div()
                                .w(px(56.0))
                                .text_color(c(t.text[2]))
                                .child(clock.rsplit(' ').next().unwrap_or("").to_string()),
                        )
                        .child(div().size(px(8.0)).rounded_full().bg(c(colour)))
                        .child(div().flex_1().truncate().child(wording::printable(&e.summary)))
                        .child(
                            div()
                                .text_size(px(11.5))
                                .text_color(c(t.text[2]))
                                .truncate()
                                .max_w(px(320.0))
                                .child(e.source.clone()),
                        ),
                    id2("ev", self.nav, i as u64),
                    i,
                    self.reduced(),
                )
                .into_any_element(),
            );
        }
        card(t)
            .size_full()
            .p(px(16.0))
            .child(card_title(t, "Everything Vigil noticed or did, newest first"))
            .child(
                div()
                    .id(id("timeline-rows", self.nav))
                    .flex_1()
                    .min_h(px(0.0))
                    .overflow_y_scroll()
                    .children(rows)
                    .when(d.events.is_empty(), |el| {
                        el.child(div().pt(px(8.0)).text_color(c(t.text[2])).child("Nothing yet."))
                    }),
            )
            .into_any_element()
    }

    /// Areas and tabs whose engines arrive later: what they will do, and what works today.
    fn coming(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let a = &AREAS[self.area];
        let tab = a.tabs[self.tab[self.area]];
        let (when, what, today): (&str, &str, Option<&'static str>) = match (a.id, tab) {
            ("network", "DNS") => (
                "milestone 3",
                "Which program looked up which name, and what it got back, from the event sensor.",
                None,
            ),
            ("network", "LAN") => ("milestone 6", "Devices on your home network and new-device alerts.", None),
            ("processes", "Secrets") => (
                "milestone 3",
                "Programs holding your SSH keys, browser profiles, wallets and tokens open.",
                Some("python3 -m vigil.tasks scan"),
            ),
            ("autostart", _) => (
                "milestone 4",
                "Everything that starts by itself, with a finding the moment something new appears.",
                Some("python3 -m vigil.persist scan"),
            ),
            ("files", _) => (
                "milestone 4",
                "Archives, documents and disguised files, inspected without opening them.",
                Some("python3 -m vigil.files"),
            ),
            ("software", _) => (
                "milestone 4",
                "PKGBUILD review, installed packages, Flatpak permissions, extensions and CVEs.",
                Some("python3 -m vigil.pkg"),
            ),
            ("guard", _) => (
                "milestone 6",
                "Firewall, SSH, sysctl hardening, Secure Boot, disk encryption and updates, each with a fix.",
                None,
            ),
            ("canaries", _) => {
                ("milestone 6", "Decoy credentials that tell you the instant anything reads them.", None)
            }
            ("home", "Storylines") | ("cases", _) => (
                "milestone 5",
                "Findings from every area linked into stories, cases, notes and exports.",
                Some("python3 -m vigil.cases"),
            ),
            _ => ("a later milestone", "", None),
        };
        let mut c_ = card(t)
            .p(px(28.0))
            .gap(px(10.0))
            .max_w(px(760.0))
            .child(gpui::svg().path(format!("icons/{}.svg", a.id)).size(px(28.0)).text_color(c(t.accent)))
            .child(div().text_size(px(19.0)).child(format!("{} · {}", a.name, tab)))
            .child(div().text_color(c(t.text[1])).child(what.to_string()))
            .child(div().text_color(c(t.text[2])).child(format!(
                "Coming in {when}. Until then this page stays empty rather than show anything made up."
            )));
        if let Some(cmd) = today {
            c_ = c_.child(
                div()
                    .mt(px(8.0))
                    .pt(px(12.0))
                    .border_t_1()
                    .border_color(c(t.line[0]))
                    .flex()
                    .items_center()
                    .gap(px(12.0))
                    .child(div().text_color(c(t.text[2])).child("Today, Vigil 1 does this:"))
                    .child(div().flex_1().font_family(t.mono_fonts[0]).child(cmd))
                    .child(button(t, "copy-v1", "Copy", false).on_click(cx.listener(
                        move |this, _: &ClickEvent, _w, cx| {
                            this.copy(cmd.to_string(), "the command", cx);
                            cx.notify();
                        },
                    ))),
            );
        }
        c_.into_any_element()
    }

    // ---- the detail panel ----------------------------------------------------------------

    /// The inspector: the selection's details, or (nothing selected) an overview of the page.
    pub fn inspector(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let body = match self.detail(cx) {
            Some(d) => d,
            None => match (self.area, self.tab[self.area]) {
                (1, 0) | (1, 1) => self.network_overview(cx),
                (2, _) => self.processes_overview(cx),
                _ => self.timeline_overview(),
            },
        };
        card(t).id("inspector").size_full().overflow_y_scroll().p(px(18.0)).child(body).into_any_element()
    }

    fn detail(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let d = self.data.as_ref()?;
        let sel = self.sel.clone()?;
        let t = &self.theme;
        let key_n = match &sel {
            Sel::Proc(p) => *p as u64,
            Sel::Program(k) | Sel::Addr(k) => hash01(k).to_bits() as u64,
        };
        let close = div()
            .id("detail-close")
            .size(px(28.0))
            .flex()
            .items_center()
            .justify_center()
            .rounded(px(t.radius_sm))
            .cursor_pointer()
            .hover(|s| s.bg(ca(Rgba(0xffffff12), 1.0)))
            .child(gpui::svg().path("icons/close.svg").size(px(16.0)).text_color(c(t.text[1])))
            .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                this.sel = None;
                cx.notify();
            }));
        let section = |title: &str| {
            div().pt(px(16.0)).pb(px(6.0)).text_size(px(11.5)).text_color(c(t.text[2])).child(title.to_string())
        };
        let kv = |k: &str, v: String| {
            div()
                .py(px(4.0))
                .flex()
                .gap(px(10.0))
                .child(div().w(px(96.0)).text_color(c(t.text[2])).child(k.to_string()))
                .child(div().flex_1().child(v))
        };
        let body: gpui::Div = match &sel {
            Sel::Proc(pid) => {
                let p = d.procs.processes.iter().find(|p| p.pid == *pid)?;
                let socks: Vec<&Socket> = d.net.sockets.iter().filter(|s| s.pids.contains(pid)).collect();
                let cmd = p.cmdline.join(" ");
                let mut chain = vec![];
                for (i, a) in p.ancestry.iter().enumerate().take(8) {
                    let apid = a.pid;
                    chain.push(
                        div()
                            .id(id("anc", i as u64))
                            .py(px(5.0))
                            .px(px(8.0))
                            .rounded(px(t.radius_sm))
                            .cursor_pointer()
                            .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                            .flex()
                            .gap(px(8.0))
                            .child(div().text_color(c(t.text[2])).child("↑"))
                            .child(div().flex_1().child(wording::printable(&a.name)))
                            .child(div().text_color(c(t.text[2])).child(apid.to_string()))
                            .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                                this.sel = Some(Sel::Proc(apid));
                                this.reveal.set(Some(gpui::ScrollStrategy::Center));
                                cx.notify();
                            })),
                    );
                }
                let cmd2 = cmd.clone();
                div()
                    .child(div().text_size(px(19.0)).child(wording::printable(&p.name)))
                    .child(
                        div()
                            .pt(px(6.0))
                            .flex()
                            .gap(px(6.0))
                            .child(chip(format!("pid {}", p.pid), t.text[1]))
                            .child(chip(p.user.clone(), t.text[1]))
                            .when(p.exe_deleted, |el| el.child(chip("file deleted while running", t.warn))),
                    )
                    .children(self.findings_block(proc_findings(d, *pid), cx))
                    .child(section("COMMAND LINE"))
                    .child(
                        div()
                            .p(px(10.0))
                            .rounded(px(t.radius_sm))
                            .bg(c(t.bg[1]))
                            .font_family(t.mono_fonts[0])
                            .text_size(px(12.0))
                            .child(wording::printable(if cmd.is_empty() { "(none: a kernel thread)" } else { &cmd })),
                    )
                    .child(
                        div()
                            .pt(px(8.0))
                            .flex()
                            .gap(px(8.0))
                            .child(button(t, "copy-cmd", "Copy command line", false).on_click(cx.listener(
                                move |this, _: &ClickEvent, _w, cx| {
                                    this.copy(cmd2.clone(), "the command line", cx);
                                    cx.notify();
                                },
                            )))
                            .child(button(t, "pivot", "Its connections", false).on_click(cx.listener(
                                |this, _: &ClickEvent, _w, cx| {
                                    this.act(vigil_ui_core::keymap::Action::Pivot);
                                    cx.notify();
                                },
                            ))),
                    )
                    .child(section("DETAILS"))
                    .child(kv(
                        "CPU · memory",
                        format!(
                            "{} · {}",
                            p.cpu_pct.map_or("-".into(), |c| format!("{c:.1}% of one core")),
                            p.rss_kb.map_or("-".into(), mem)
                        ),
                    ))
                    .child(kv(
                        "Program file",
                        p.exe.clone().map_or("(not readable)".into(), |e| wording::printable(&e)),
                    ))
                    .child(kv("Started", p.started.map_or("-".into(), |s| format!("{} ({})", self.clock(s), ago(s)))))
                    .child(kv("Program", wording::printable(&p.key)))
                    .child(section("STARTED BY"))
                    .children(chain)
                    .when(p.ancestry.is_empty(), |el| {
                        el.child(div().text_color(c(t.text[2])).child("No visible parent."))
                    })
                    .child(section(&format!("NETWORK ({})", socks.len())))
                    .children(
                        socks
                            .iter()
                            .take(12)
                            .map(|s| kv(&s.proto, format!("{} {}", endpoint(&s.remote_ip, s.remote_port), s.state))),
                    )
            }
            Sel::Program(key) => {
                let socks: Vec<&Socket> =
                    d.net.sockets.iter().filter(|s| s.program.as_deref() == Some(key.as_str())).collect();
                let pids: BTreeSet<u32> = socks.iter().flat_map(|s| s.pids.clone()).collect();
                let proc_ = pids.iter().next().and_then(|p| d.net.processes.get(p));
                let first = d
                    .events
                    .iter()
                    .filter(|e| {
                        e.kind == "first-seen" && e.detail.get("program").and_then(|v| v.as_str()) == Some(key.as_str())
                    })
                    .map(|e| e.ts)
                    .fold(f64::NAN, f64::min);
                let addrs: BTreeSet<String> =
                    socks.iter().filter(|s| s.kind == "connection").map(|s| s.remote_ip.clone()).collect();
                div()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(10.0))
                            .child(self.app_icon(key, 30.0))
                            .child(div().text_size(px(19.0)).child(program_name(d, key))),
                    )
                    .child(
                        div()
                            .pt(px(6.0))
                            .flex()
                            .gap(px(6.0))
                            .child(chip(
                                count(socks.iter().filter(|s| s.kind == "connection").count(), "connection"),
                                t.live,
                            ))
                            .child(chip(count(addrs.len(), "address"), t.text[1])),
                    )
                    .children(self.findings_block(program_findings(d, key), cx))
                    .child(section("PROGRAM"))
                    .child(kv("Path", wording::printable(key)))
                    .child(kv("Processes", pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")))
                    .child(kv("User", proc_.map_or("-".into(), |p| p.user.clone())))
                    .child(kv(
                        "First online",
                        if first.is_nan() {
                            "before this history".into()
                        } else {
                            format!("{} ({})", self.clock(first), ago(first))
                        },
                    ))
                    .child(div().pt(px(8.0)).child(button(t, "to-proc", "Show the process", false).on_click(
                        cx.listener(|this, _: &ClickEvent, _w, cx| {
                            this.act(vigil_ui_core::keymap::Action::Pivot);
                            cx.notify();
                        }),
                    )))
                    .child(section("CONNECTIONS"))
                    .children(socks.iter().filter(|s| s.kind == "connection").take(20).map(|s| {
                        div()
                            .py(px(5.0))
                            .flex()
                            .gap(px(8.0))
                            .border_t_1()
                            .border_color(c(t.line[0]))
                            .child(div().text_color(c(t.text[2])).child(if s.direction == "in" {
                                "↙"
                            } else {
                                "↗"
                            }))
                            .child(div().flex_1().child(endpoint(&s.remote_ip, s.remote_port)))
                            .child(div().text_color(c(t.text[2])).child(scope_of(&s.remote_ip)))
                            .child(state_view(t, &s.state))
                    }))
            }
            Sel::Addr(ip) => {
                let socks: Vec<&Socket> = d.net.sockets.iter().filter(|s| &s.remote_ip == ip).collect();
                let progs: BTreeSet<String> = socks.iter().filter_map(|s| s.program.clone()).collect();
                let ports: BTreeSet<String> = socks.iter().map(|s| service_name(&s.proto, s.remote_port)).collect();
                let mut prog_rows = vec![];
                for (i, k) in progs.iter().enumerate() {
                    let key = k.clone();
                    prog_rows.push(
                        div()
                            .id(id("addr-prog", i as u64))
                            .py(px(6.0))
                            .px(px(6.0))
                            .flex()
                            .items_center()
                            .gap(px(10.0))
                            .rounded(px(t.radius_sm))
                            .cursor_pointer()
                            .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                            .child(self.app_icon(k, 20.0))
                            .child(div().flex_1().truncate().child(program_name(d, k)))
                            .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                                this.sel = Some(Sel::Program(key.clone()));
                                cx.notify();
                            })),
                    );
                }
                let where_ = match scope_of(ip) {
                    "internet" => "on the internet",
                    "lan" => "on your local network",
                    "link-local" => "on this network link",
                    other => other,
                };
                div()
                    .child(div().text_size(px(19.0)).child(ip.clone()))
                    .child(
                        div()
                            .pt(px(6.0))
                            .flex()
                            .gap(px(6.0))
                            .child(chip(where_.to_string(), t.live))
                            .child(chip(count(socks.len(), "connection"), t.text[1])),
                    )
                    .child(section("SERVICES"))
                    .child(div().child(ports.into_iter().collect::<Vec<_>>().join(", ")))
                    .child(section("PROGRAMS TALKING TO IT"))
                    .children(prog_rows)
                    .when(progs.is_empty(), |el| {
                        el.child(div().text_color(c(t.text[2])).child("Its program is hidden from this view."))
                    })
                    .child(section("CONNECTIONS"))
                    .children(socks.iter().take(16).map(|s| {
                        div()
                            .py(px(5.0))
                            .flex()
                            .items_center()
                            .gap(px(8.0))
                            .border_t_1()
                            .border_color(c(t.line[0]))
                            .child(div().flex_1().child(format!("{} → {}", s.local_port, s.remote_port)))
                            .child(state_view(t, &s.state))
                    }))
            }
        };
        let _ = key_n;
        Some(
            div()
                .relative()
                .child(div().absolute().top(px(-8.0)).right(px(-8.0)).child(close))
                .child(body)
                .into_any_element(),
        )
    }

    /// "Why Vigil flagged it": each finding with its reasons, where it came from, and the
    /// commands to check or fix it (copy only; Run mode arrives in milestone 5).
    fn findings_block(&self, fs: Vec<&vigil_model::finding::Finding>, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let t = &self.theme;
        if fs.is_empty() {
            return vec![];
        }
        let mut out = vec![div()
            .pt(px(16.0))
            .pb(px(6.0))
            .text_size(px(11.5))
            .text_color(c(t.text[2]))
            .child("WHY VIGIL FLAGGED IT")
            .into_any_element()];
        for (i, f) in fs.into_iter().enumerate() {
            let colour = sev_colour(t, f.severity);
            let attack = if f.attack.is_empty() {
                String::new()
            } else {
                format!(" · ATT&CK {}", f.attack.iter().map(|a| a.id.as_str()).collect::<Vec<_>>().join(", "))
            };
            let mut block = div()
                .py(px(10.0))
                .border_t_1()
                .border_color(c(t.line[0]))
                .flex()
                .flex_col()
                .gap(px(6.0))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.0))
                        .child(chip(f.severity.as_str(), colour))
                        .child(div().flex_1().child(wording::printable(&f.title))),
                )
                .child(div().text_color(c(t.text[1])).child(wording::printable(&f.summary)))
                .children(f.signals.iter().map(|sig| {
                    div()
                        .flex()
                        .gap(px(8.0))
                        .text_size(px(12.0))
                        .child(
                            div()
                                .w(px(36.0))
                                .flex_none()
                                .text_color(c(t.text[2]))
                                .child(format!("{:.0}%", sig.strength * 100.0)),
                        )
                        .child(div().flex_1().min_w(px(0.0)).child(wording::printable(&sig.text)))
                }))
                .when_some(f.likely.as_ref(), |el, l| {
                    el.child(div().text_size(px(12.0)).text_color(c(t.text[2])).child(wording::printable(l)))
                })
                .child(div().text_size(px(11.5)).text_color(c(t.text[2])).child(format!(
                    "Source: {} check {}, read {} at {}{attack}",
                    f.source.tool,
                    f.source.check,
                    f.source.data.as_str().unwrap_or(""),
                    self.clock(f.source.when),
                )));
            if let Some(panel) = &f.fixes {
                for (group, opts) in [("Check", &panel.check), ("Fix", &panel.fix)] {
                    for (j, o) in opts.iter().enumerate() {
                        let cmd = o.commands.iter().map(|c| c.text.clone()).collect::<Vec<_>>().join("\n");
                        let n = (i * 100 + j + if group == "Fix" { 50 } else { 0 }) as u64;
                        let mut opt = div().pt(px(4.0)).flex().flex_col().gap(px(4.0)).child(
                            div()
                                .flex()
                                .gap(px(8.0))
                                .text_size(px(12.0))
                                .child(div().text_color(c(t.text[2])).child(group))
                                .child(div().flex_1().child(o.title.clone()))
                                .child(div().text_color(c(t.text[2])).child(o.risk_label.clone())),
                        );
                        if !cmd.is_empty() {
                            let copy = cmd.clone();
                            opt = opt.child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(8.0))
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w(px(0.0))
                                            .px(px(8.0))
                                            .py(px(5.0))
                                            .rounded(px(t.radius_sm))
                                            .bg(c(t.bg[1]))
                                            .font_family(t.mono_fonts[0])
                                            .text_size(px(11.5))
                                            .child(cmd),
                                    )
                                    .child(button(t, id("fx-copy", n), "Copy", false).on_click(cx.listener(
                                        move |this, _: &ClickEvent, _w, cx| {
                                            this.copy(copy.clone(), "the command", cx);
                                            cx.notify();
                                        },
                                    ))),
                            );
                        }
                        for st in &o.steps {
                            opt =
                                opt.child(div().text_size(px(12.0)).text_color(c(t.text[1])).child(format!("• {st}")));
                        }
                        block = block.child(opt);
                    }
                }
            }
            out.push(block.into_any_element());
        }
        out
    }

    // ---- overviews (the inspector with nothing selected) -----------------------------------

    fn section_head(&self, title: &str, note: String) -> gpui::Div {
        let t = &self.theme;
        div()
            .pt(px(18.0))
            .pb(px(8.0))
            .flex()
            .items_center()
            .child(div().flex_1().text_size(px(11.5)).text_color(c(t.text[2])).child(title.to_string()))
            .child(div().text_size(px(11.5)).text_color(c(t.text[2])).child(note))
    }

    /// One line of a ranked list: icon, name, value, and a thin bar under the name.
    #[allow(clippy::too_many_arguments)]
    fn rank_row(
        &self,
        key: (&'static str, u64),
        icon: Option<&str>,
        name: String,
        value: String,
        frac: f32,
        colour: Rgba,
        sel: Option<Sel>,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        let t = &self.theme;
        div()
            .id(key)
            .py(px(5.0))
            .px(px(6.0))
            .mx(px(-6.0))
            .flex()
            .items_center()
            .gap(px(10.0))
            .rounded(px(t.radius_sm))
            .when(sel.is_some(), |el| el.cursor_pointer().hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0))))
            .when_some(icon, |el, i| el.child(self.app_icon(i, 18.0)))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.0))
                    .flex()
                    .flex_col()
                    .gap(px(3.0))
                    .child(
                        div()
                            .flex()
                            .gap(px(8.0))
                            .child(div().flex_1().min_w(px(0.0)).truncate().child(name))
                            .child(div().flex_none().text_color(c(t.text[1])).child(value)),
                    )
                    .child(
                        div().h(px(3.0)).w_full().rounded(px(2.0)).bg(c(t.bg[3])).child(
                            div().h_full().rounded(px(2.0)).bg(c(colour)).w(gpui::relative(frac.clamp(0.0, 1.0))),
                        ),
                    ),
            )
            .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                if let Some(s) = sel.clone() {
                    this.sel = Some(s);
                    this.reveal.set(Some(gpui::ScrollStrategy::Center));
                    cx.notify();
                }
            }))
    }

    fn stat(&self, label: &str, value: String) -> gpui::Div {
        let t = &self.theme;
        div()
            .flex_1()
            .flex()
            .flex_col()
            .gap(px(2.0))
            .child(div().text_size(px(20.0)).child(value))
            .child(div().text_size(px(11.5)).text_color(c(t.text[2])).child(label.to_string()))
    }

    fn processes_overview(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        // Per program: processes, CPU, memory.
        let mut per: BTreeMap<String, ProgUse> = BTreeMap::new();
        for p in &d.procs.processes {
            if p.exe.is_none() && p.cmdline.is_empty() {
                continue; // kernel threads
            }
            let e = per.entry(p.key.clone()).or_insert((0, 0.0, 0, p.exe.clone().unwrap_or_default()));
            e.0 += 1;
            e.1 += p.cpu_pct.unwrap_or(0.0);
            e.2 += p.rss_kb.unwrap_or(0);
        }
        let kernel = d.procs.processes.iter().filter(|p| p.exe.is_none() && p.cmdline.is_empty()).count();
        let users: BTreeSet<&str> = d.procs.processes.iter().map(|p| p.user.as_str()).collect();
        let total_cpu: f32 = d.procs.processes.iter().filter_map(|p| p.cpu_pct).sum::<f32>().max(0.0);
        let mut by_cpu: Vec<(&String, &ProgUse)> = per.iter().collect();
        by_cpu.sort_by(|a, b| b.1 .1.partial_cmp(&a.1 .1).unwrap_or(std::cmp::Ordering::Equal));
        let mut by_mem: Vec<(&String, &ProgUse)> = per.iter().collect();
        by_mem.sort_by_key(|x| std::cmp::Reverse(x.1 .2));
        let name_of = |key: &str, n: usize| {
            let name =
                d.procs.processes.iter().find(|p| p.key == key).map_or(key.to_string(), |p| display_name(Some(p), key));
            if n > 1 {
                format!("{} ×{n}", wording::printable(&name))
            } else {
                wording::printable(&name)
            }
        };
        let cpu_max = by_cpu.first().map_or(1.0, |x| x.1 .1).max(1.0);
        let mem_max = by_mem.first().map_or(1, |x| x.1 .2).max(1) as f32;
        let mut cpu_rows = vec![];
        for (i, (key, (n, cpu, _, exe))) in by_cpu.iter().take(7).enumerate() {
            let pid = main_pid(d, key);
            cpu_rows.push(self.rank_row(
                ("ov-cpu", i as u64),
                Some(exe.as_str()),
                name_of(key, *n),
                format!("{cpu:.1}%"),
                cpu / cpu_max,
                t.accent,
                pid.map(Sel::Proc),
                cx,
            ));
        }
        let mut mem_rows = vec![];
        for (i, (key, (n, _, kb, exe))) in by_mem.iter().take(7).enumerate() {
            let pid = main_pid(d, key);
            mem_rows.push(self.rank_row(
                ("ov-mem", i as u64),
                Some(exe.as_str()),
                name_of(key, *n),
                mem(*kb),
                *kb as f32 / mem_max,
                t.live,
                pid.map(Sel::Proc),
                cx,
            ));
        }
        let mut user_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for p in &d.procs.processes {
            *user_counts.entry(p.user.as_str()).or_insert(0) += 1;
        }
        let mut user_rows: Vec<(&str, usize)> = user_counts.into_iter().collect();
        user_rows.sort_by_key(|x| std::cmp::Reverse(x.1));
        let ucount = d.procs.processes.len().max(1) as f32;
        let hidden: usize = d.procs.unreadable_by_uid.values().sum();
        let flagged: Vec<&vigil_model::finding::Finding> = d.findings.iter().filter(|f| f.tool == "tasks").collect();
        let mut flagged_rows = vec![];
        for (i, f) in flagged.iter().take(8).enumerate() {
            let pid: Option<u32> = f.subject.rsplit(':').next().and_then(|x| x.parse().ok());
            let colour = sev_colour(t, f.severity);
            flagged_rows.push(
                div()
                    .id(("ov-flag", i as u64))
                    .py(px(6.0))
                    .px(px(6.0))
                    .mx(px(-6.0))
                    .flex()
                    .items_center()
                    .gap(px(10.0))
                    .rounded(px(t.radius_sm))
                    .cursor_pointer()
                    .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                    .child(chip(f.severity.as_str(), colour))
                    .child(div().flex_1().min_w(px(0.0)).truncate().child(wording::printable(&f.title)))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.sel = pid.map(Sel::Proc);
                        this.reveal.set(Some(gpui::ScrollStrategy::Center));
                        cx.notify();
                    })),
            );
        }
        div()
            .flex()
            .flex_col()
            .child(div().text_size(px(16.0)).child("All processes"))
            .child(
                div()
                    .pt(px(12.0))
                    .flex()
                    .child(self.stat("running", d.procs.processes.len().to_string()))
                    .child(self.stat("programs", per.len().to_string()))
                    .child(self.stat("users", users.len().to_string()))
                    .child(self.stat("CPU in use", format!("{total_cpu:.0}%"))),
            )
            .child(self.section_head("FLAGGED BY VIGIL", count(flagged.len(), "finding")))
            .children(flagged_rows)
            .when(flagged.is_empty(), |el| {
                el.child(div().text_size(px(12.5)).text_color(c(t.text[2])).child(
                    "No process looks unusual to Vigil's checks right now (checked every 10 seconds). \
                     That is what the checks found, not a promise that everything is safe.",
                ))
            })
            .child(self.section_head("USING THE MOST CPU", "share of one core".into()))
            .children(cpu_rows)
            .child(self.section_head("USING THE MOST MEMORY", "resident".into()))
            .children(mem_rows)
            .child(self.section_head("BY USER", format!("{kernel} kernel threads")))
            .children(user_rows.into_iter().take(6).enumerate().map(|(i, (u, n))| {
                div()
                    .id(("ov-user", i as u64))
                    .py(px(4.0))
                    .flex()
                    .gap(px(10.0))
                    .child(div().flex_1().truncate().child(u.to_string()))
                    .child(
                        div().w(px(110.0)).h(px(3.0)).mt(px(8.0)).rounded(px(2.0)).bg(c(t.bg[3])).child(
                            div().h_full().rounded(px(2.0)).bg(c(t.text[2])).w(gpui::relative(n as f32 / ucount)),
                        ),
                    )
                    .child(div().w(px(36.0)).flex().justify_end().text_color(c(t.text[1])).child(n.to_string()))
            }))
            .when(hidden > 0, |el| {
                el.child(div().pt(px(14.0)).text_size(px(12.0)).text_color(c(t.text[2])).child(format!(
                    "{hidden} processes belong to other users or are protected: names and pids are shown, \
                     details are limited. The installed daemon sees them all."
                )))
            })
            .child(div().pt(px(14.0)).text_size(px(12.0)).text_color(c(t.text[2])).child(
                "Click a process for its command line, parent chain and connections. Click it again to come back here.",
            ))
            .into_any_element()
    }

    fn network_overview(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        let socks: Vec<&Socket> = real_connections(d).collect();
        let mut per: BTreeMap<String, (usize, BTreeSet<&str>)> = BTreeMap::new();
        let mut states: BTreeMap<&str, usize> = BTreeMap::new();
        let mut services: BTreeMap<String, usize> = BTreeMap::new();
        let (mut internet, mut lan, mut inbound) = (0usize, 0usize, 0usize);
        for s in &socks {
            if let Some(k) = &s.program {
                let e = per.entry(k.clone()).or_default();
                e.0 += 1;
                e.1.insert(s.remote_ip.as_str());
            }
            let st = match s.state.as_str() {
                "ESTABLISHED" => "Open",
                "SYN_SENT" | "SYN_RECV" | "NEW_SYN_RECV" => "Connecting",
                _ => "Closing",
            };
            *states.entry(st).or_insert(0) += 1;
            let port = if s.direction == "in" { s.local_port } else { s.remote_port };
            *services.entry(service_name(&s.proto, port)).or_insert(0) += 1;
            match scope_of(&s.remote_ip) {
                "lan" | "link-local" => lan += 1,
                _ => internet += 1,
            }
            if s.direction == "in" {
                inbound += 1;
            }
        }
        let listening = d.net.sockets.iter().filter(|s| s.kind == "listen").count();
        let mut progs: Vec<(String, (usize, BTreeSet<&str>))> = per.into_iter().collect();
        progs.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
        let pmax = progs.first().map_or(1, |x| x.1 .0).max(1) as f32;
        let alerts: Vec<&vigil_model::finding::Finding> = d.findings.iter().filter(|f| f.tool == "net").collect();
        let mut alert_rows = vec![];
        for (i, f) in alerts.iter().take(6).enumerate() {
            let key = f.evidence.iter().find(|e| e.kind == "program").and_then(|e| e.value.as_str()).map(String::from);
            alert_rows.push(
                div()
                    .id(("ov-alert", i as u64))
                    .py(px(6.0))
                    .px(px(6.0))
                    .mx(px(-6.0))
                    .flex()
                    .items_center()
                    .gap(px(10.0))
                    .rounded(px(t.radius_sm))
                    .cursor_pointer()
                    .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                    .child(chip(f.severity.as_str(), sev_colour(t, f.severity)))
                    .child(div().flex_1().min_w(px(0.0)).truncate().child(wording::printable(&f.title)))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.sel = key.clone().map(Sel::Program);
                        cx.notify();
                    })),
            );
        }
        let mut prog_rows = vec![];
        for (i, (k, (n, addrs))) in progs.iter().take(9).enumerate() {
            prog_rows.push(self.rank_row(
                ("ov-prog", i as u64),
                Some(k.as_str()),
                program_name(d, k),
                format!("{n} · {} addr", addrs.len()),
                *n as f32 / pmax,
                t.live,
                Some(Sel::Program(k.clone())),
                cx,
            ));
        }
        let mut svc: Vec<(String, usize)> = services.into_iter().collect();
        svc.sort_by_key(|x| std::cmp::Reverse(x.1));
        let smax = svc.first().map_or(1, |x| x.1).max(1) as f32;
        let total = socks.len().max(1) as f32;
        div()
            .flex()
            .flex_col()
            .child(div().text_size(px(16.0)).child("Talking right now"))
            .when(!alerts.is_empty(), |el| {
                el.child(self.section_head("FLAGGED BY VIGIL", count(alerts.len(), "alert"))).children(alert_rows)
            })
            .child(
                div()
                    .pt(px(12.0))
                    .flex()
                    .child(self.stat("connections", socks.len().to_string()))
                    .child(self.stat("programs", progs.len().to_string()))
                    .child(self.stat("inbound", inbound.to_string()))
                    .child(self.stat("listening", listening.to_string())),
            )
            .child(
                div().pt(px(14.0)).flex().h(px(6.0)).child(
                    div()
                        .flex()
                        .w_full()
                        .h(px(6.0))
                        .rounded(px(3.0))
                        .overflow_hidden()
                        .bg(c(t.bg[3]))
                        .child(div().h_full().bg(c(t.live)).w(gpui::relative(internet as f32 / total)))
                        .child(div().h_full().bg(c(t.accent)).w(gpui::relative(lan as f32 / total))),
                ),
            )
            .child(
                div()
                    .pt(px(14.0))
                    .flex()
                    .flex_wrap()
                    .gap_x(px(14.0))
                    .gap_y(px(4.0))
                    .text_size(px(11.5))
                    .text_color(c(t.text[2]))
                    .child(format!("Internet {internet}"))
                    .child(format!("Local network {lan}"))
                    .children(states.iter().map(|(k, v)| format!("{k} {v}"))),
            )
            .child(self.section_head("PROGRAMS", "connections · addresses".into()))
            .children(prog_rows)
            .when(progs.is_empty(), |el| {
                el.child(div().text_color(c(t.text[2])).child("Nothing is talking to another machine."))
            })
            .child(self.section_head("SERVICES", String::new()))
            .children(svc.into_iter().take(6).enumerate().map(|(i, (name, n))| {
                div()
                    .id(("ov-svc", i as u64))
                    .py(px(4.0))
                    .flex()
                    .gap(px(10.0))
                    .child(div().w(px(120.0)).truncate().child(name))
                    .child(
                        div()
                            .flex_1()
                            .h(px(3.0))
                            .mt(px(8.0))
                            .rounded(px(2.0))
                            .bg(c(t.bg[3]))
                            .child(div().h_full().rounded(px(2.0)).bg(c(t.live)).w(gpui::relative(n as f32 / smax))),
                    )
                    .child(div().w(px(30.0)).flex().justify_end().text_color(c(t.text[1])).child(n.to_string()))
            }))
            .child(
                div()
                    .pt(px(14.0))
                    .text_size(px(12.0))
                    .text_color(c(t.text[2]))
                    .child("Click a program or an address for its details. Click it again to come back here."),
            )
            .into_any_element()
    }

    fn timeline_overview(&self) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        let day = vigil_model::finding::now() - 86400.0;
        let mut kinds: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for e in &d.events {
            let k = kinds.entry(e.kind.as_str()).or_default();
            k.0 += 1;
            if e.ts > day {
                k.1 += 1;
            }
        }
        let word = |k: &str| match k {
            "first-seen" => "New on the network".to_string(),
            "finding" => "Findings".to_string(),
            "short-lived" => "Short-lived programs that connected".to_string(),
            "daemon" => "Vigil itself".to_string(),
            other => other.to_string(),
        };
        div()
            .flex()
            .flex_col()
            .child(div().text_size(px(16.0)).child("This week"))
            .child(
                div()
                    .pt(px(12.0))
                    .flex()
                    .child(self.stat("events", d.events.len().to_string()))
                    .child(self.stat("today", d.events.iter().filter(|e| e.ts > day).count().to_string())),
            )
            .child(self.section_head("BY KIND", "all · today".into()))
            .children(kinds.into_iter().map(|(k, (all, today))| {
                div()
                    .py(px(5.0))
                    .flex()
                    .gap(px(10.0))
                    .border_t_1()
                    .border_color(c(t.line[0]))
                    .child(div().flex_1().child(word(k)))
                    .child(div().text_color(c(t.text[1])).child(format!("{all} · {today}")))
            }))
            .child(
                div()
                    .pt(px(14.0))
                    .text_size(px(12.0))
                    .text_color(c(t.text[2]))
                    .child("Findings join this timeline in milestone 3, with where each came from."),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, ppid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            key: format!("/bin/p{pid}"),
            name: format!("p{pid}"),
            comm: String::new(),
            exe: None,
            exe_deleted: false,
            cmdline: vec![],
            uid: 0,
            user: "root".into(),
            ppid,
            parent: None,
            ancestry: vec![],
            started: None,
            rss_kb: None,
            cpu_pct: None,
        }
    }

    #[test]
    fn tree_order_nests_children_under_parents() {
        let procs = vec![p(1, 0), p(5, 1), p(7, 5), p(3, 1), p(9, 42)];
        assert_eq!(tree_order(&procs), vec![(1, 0), (3, 1), (5, 1), (7, 2), (9, 0)]);
    }
}
