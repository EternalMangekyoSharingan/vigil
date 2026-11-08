//! The areas, fed by the daemon's last look.
//!
//! Home (overview, first sightings), Network (live map, connections, time machine),
//! Processes (tree, table), Cases (the event log) show real data. Areas whose engines
//! arrive in later milestones say so, and say what works today; none shows made-up data.

use gpui::{
    canvas, div, point, prelude::*, px, relative, AnyElement, ClickEvent, Context, MouseButton, MouseDownEvent,
    PathBuilder, SharedString, TextAlign, TextRun,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::f32::consts::{PI, TAU};
use vigil_model::host::{ProcessInfo, Socket};
use vigil_model::netaddr::scope_of;
use vigil_model::wording;
use vigil_ui_core::areas::AREAS;
use vigil_ui_core::motion::{self, MarkFrame};
use vigil_ui_core::settings::View;
use vigil_ui_core::theme::Rgba;

use crate::ui::{ago, button, c, ca, card, card_title, chip, enter, id, id2, kbd, row_enter, slide_in};
use crate::{live::Snapshot, mark, Conn, Sel, Vigil, DETAIL_W};

/// "Firefox" for well-known programs, else the collector's name ("http.server (python3)").
pub fn display_name(p: Option<&ProcessInfo>, key: &str) -> String {
    let exe = p.and_then(|p| p.exe.as_deref()).unwrap_or(key.split(' ').next().unwrap_or(key));
    let base = exe.rsplit('/').next().unwrap_or(exe).trim_end_matches(" (deleted)").to_lowercase();
    match wording::FRIENDLY.iter().find(|(k, _)| *k == base) {
        Some((_, v)) => v.to_string(),
        None => p.map_or_else(|| wording::friendly_program(None, Some(key), None), |p| p.name.clone()),
    }
}

fn program_name(d: &Snapshot, key: &str) -> String {
    let p = d
        .net
        .sockets
        .iter()
        .find(|s| s.program.as_deref() == Some(key))
        .and_then(|s| s.pid)
        .and_then(|pid| d.net.processes.get(&pid));
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
fn real_connections(d: &Snapshot) -> impl Iterator<Item = &Socket> {
    d.net.sockets.iter().filter(|s| s.kind == "connection" && scope_of(&s.remote_ip) != "loopback")
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

// ---- the network map's layout --------------------------------------------------------------

pub struct MapNode {
    pub key: String,
    pub label: String,
    pub x: f32,
    pub y: f32,
    pub count: usize,
}

pub struct MapLayout {
    pub progs: Vec<MapNode>,
    pub dests: Vec<MapNode>,
    /// (program, destination, inbound, live)
    pub edges: Vec<(usize, usize, bool, bool)>,
}

fn hash01(s: &str) -> f32 {
    let mut h: u32 = 2166136261;
    for b in s.bytes() {
        h = (h ^ u32::from(b)).wrapping_mul(16777619);
    }
    (h % 10_000) as f32 / 10_000.0
}

/// Programs on an inner ring around this PC, each program's destinations fanned out on the
/// outer ring around its angle. Positions are relative to the map's centre.
pub fn map_layout(d: &Snapshot, w: f32, h: f32) -> MapLayout {
    let mut per_prog: BTreeMap<String, Vec<&Socket>> = BTreeMap::new();
    for s in real_connections(d) {
        let key = s
            .program
            .clone()
            .unwrap_or_else(|| format!("hidden:{}", s.hidden.as_ref().map_or("unknown", |h| h.reason.as_str())));
        per_prog.entry(key).or_default().push(s);
    }
    let mut ranked: Vec<(String, Vec<&Socket>)> = per_prog.into_iter().collect();
    ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    ranked.truncate(20);
    let n = ranked.len().max(1) as f32;
    let m = w.min(h);
    let (r1, r2) = (m * 0.2, m * 0.41);
    let mut progs = vec![];
    let mut dests: Vec<MapNode> = vec![];
    let mut dest_index: HashMap<String, usize> = HashMap::new();
    let mut edges = vec![];
    for (i, (key, socks)) in ranked.iter().enumerate() {
        let a = -PI / 2.0 + TAU * i as f32 / n;
        let label = if let Some(reason) = key.strip_prefix("hidden:") {
            vigil_sensor_label(reason)
        } else {
            program_name(d, key)
        };
        progs.push(MapNode { key: key.clone(), label, x: r1 * a.cos(), y: r1 * a.sin(), count: socks.len() });
        let mine: Vec<&&Socket> = socks.iter().collect();
        let spread = (TAU / n * 0.8).min(1.2);
        let uniq: Vec<String> = mine.iter().map(|s| s.remote_ip.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        for (j, ip) in uniq.iter().enumerate() {
            let di = *dest_index.entry(ip.clone()).or_insert_with(|| {
                let off = if uniq.len() == 1 { 0.0 } else { (j as f32 / (uniq.len() - 1) as f32 - 0.5) * spread };
                let rr = r2 * (0.92 + 0.12 * hash01(ip));
                dests.push(MapNode {
                    key: ip.clone(),
                    label: ip.clone(),
                    x: rr * (a + off).cos(),
                    y: rr * (a + off).sin(),
                    count: 0,
                });
                dests.len() - 1
            });
            dests[di].count += 1;
            let live = mine.iter().any(|s| &s.remote_ip == ip && s.state == "ESTABLISHED");
            let inbound = mine.iter().any(|s| &s.remote_ip == ip && s.direction == "in");
            edges.push((i, di, inbound, live));
        }
    }
    MapLayout { progs, dests, edges }
}

fn vigil_sensor_label(reason: &str) -> String {
    match reason {
        "other-user" => "Hidden: other users".into(),
        "closed" => "Closing".into(),
        "protected" => "Hidden: protected".into(),
        _ => "Unattributed".into(),
    }
}

impl Vigil {
    /// The items j/k move through in the current view.
    pub fn list_items(&self) -> Vec<Sel> {
        let Some(d) = &self.data else { return vec![] };
        match (self.area, self.tab[self.area]) {
            (2, 0) => tree_order(&d.procs.processes)
                .into_iter()
                .filter(|(pid, _)| d.procs.processes.iter().any(|p| p.pid == *pid && matches_filter(p, &self.filter)))
                .map(|(pid, _)| Sel::Proc(pid))
                .collect(),
            (2, 1) => {
                d.procs.processes.iter().filter(|p| matches_filter(p, &self.filter)).map(|p| Sel::Proc(p.pid)).collect()
            }
            (1, 0) => map_layout(d, 800.0, 600.0)
                .progs
                .into_iter()
                .filter(|p| !p.key.starts_with("hidden:"))
                .map(|p| Sel::Program(p.key))
                .collect(),
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
        let main: AnyElement = match &self.data {
            None => self.no_data(cx),
            Some(_) => match (self.area, self.tab[self.area]) {
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
        let detail = self.detail(cx);
        let pad = if self.settings.density == vigil_ui_core::settings::Density::Compact { 14.0 } else { t.pad };
        div()
            .flex_1()
            .min_h(px(0.0))
            .flex()
            .child(
                div().id(id("main", self.nav)).flex_1().min_w(px(0.0)).h_full().overflow_y_scroll().p(px(pad)).child(
                    enter(
                        div().flex().flex_col().gap(px(16.0)).child(main),
                        id("area", self.nav),
                        0.0,
                        motion::AREA_RISE_PX,
                        reduced,
                    ),
                ),
            )
            .when_some(detail, |d, panel| d.child(panel))
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

    fn tile(&self, i: usize, label: &str, value: String, sub: &str) -> AnyElement {
        let t = &self.theme;
        let (rise, op) = self
            .arrived
            .map_or((0.0, 1.0), |a| motion::card_rise(a.elapsed().as_secs_f32() * 1000.0, i, self.reduced()));
        card(t)
            .flex_1()
            .min_w(px(150.0))
            .p(px(16.0))
            .gap(px(4.0))
            .opacity(op)
            .relative()
            .top(px(rise))
            .child(div().text_size(px(12.0)).text_color(c(t.text[2])).child(label.to_string()))
            .child(div().text_size(px(28.0)).text_color(c(t.text[0])).child(value))
            .child(div().text_size(px(11.5)).text_color(c(t.text[2])).child(sub.to_string()))
            .into_any_element()
    }

    fn rise(&self, i: usize, el: gpui::Div) -> gpui::Div {
        let (rise, op) = self
            .arrived
            .map_or((0.0, 1.0), |a| motion::card_rise(a.elapsed().as_secs_f32() * 1000.0, i, self.reduced()));
        el.opacity(op).relative().top(px(rise))
    }

    fn home(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        let n = |k: &str| self.counter(k).round() as i64;
        let tiles = div()
            .flex()
            .flex_wrap()
            .gap(px(12.0))
            .child(self.tile(0, "Processes", n("procs").to_string(), "running now"))
            .child(self.tile(1, "Connections out", n("out").to_string(), "to other machines"))
            .child(self.tile(2, "Programs online", n("programs").to_string(), "using the network now"))
            .child(self.tile(3, "Destinations", n("dests").to_string(), "seen since history began"))
            .child(self.tile(
                4,
                "Vigil's daemon",
                format!("{} MB", n("mem")),
                &format!("up {}", wording::span(d.status.uptime_s, true)),
            ));

        // Talking now: programs by connection count, with bars.
        let mut per: BTreeMap<String, usize> = BTreeMap::new();
        for s in real_connections(d) {
            if let Some(k) = &s.program {
                *per.entry(k.clone()).or_insert(0) += 1;
            }
        }
        let mut top: Vec<(String, usize)> = per.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        top.truncate(7);
        let max = top.first().map_or(1, |x| x.1).max(1) as f32;
        let mut rows = vec![];
        for (i, (key, count)) in top.iter().enumerate() {
            let key2 = key.clone();
            let frac = *count as f32 / max;
            rows.push(
                div()
                    .id(id("talk", i as u64))
                    .py(px(7.0))
                    .px(px(8.0))
                    .rounded(px(t.radius_sm))
                    .cursor_pointer()
                    .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                    .flex()
                    .flex_col()
                    .gap(px(5.0))
                    .child(
                        div()
                            .flex()
                            .child(div().flex_1().truncate().child(program_name(d, key)))
                            .child(div().text_color(c(t.text[2])).child(format!("{count}"))),
                    )
                    .child(
                        div()
                            .h(px(4.0))
                            .w_full()
                            .rounded(px(2.0))
                            .bg(c(t.bg[3]))
                            .child(div().h_full().rounded(px(2.0)).bg(c(t.live)).w(relative(frac))),
                    )
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.set_tab(1, 1);
                        this.sel = Some(Sel::Program(key2.clone()));
                        cx.notify();
                    })),
            );
        }
        let talking = self
            .rise(5, card(t).p(px(16.0)).gap(px(6.0)).flex_1().min_w(px(320.0)))
            .child(card_title(t, "Talking now"))
            .children(rows)
            .when(top.is_empty(), |el| {
                el.child(
                    div().text_color(c(t.text[2])).child("No program has a connection to another machine right now."),
                )
            });

        let mut sources = vec![];
        for s in &d.status.sources {
            sources.push(
                div()
                    .py(px(7.0))
                    .flex()
                    .flex_col()
                    .gap(px(3.0))
                    .border_t_1()
                    .border_color(c(t.line[0]))
                    .child(
                        div()
                            .flex()
                            .gap(px(8.0))
                            .items_center()
                            .child(div().w(px(90.0)).child(s.signal.clone()))
                            .child(if s.live { chip(s.source.clone(), t.ok) } else { chip("not yet", t.text[2]) }),
                    )
                    .child(div().text_size(px(11.5)).text_color(c(t.text[2])).child(s.note.clone())),
            );
        }
        let seeing = self
            .rise(6, card(t).p(px(16.0)).gap(px(4.0)).flex_1().min_w(px(320.0)))
            .child(card_title(t, "What Vigil can and cannot see"))
            .children(sources);

        let mut recent = vec![];
        for (i, e) in d.events.iter().take(6).enumerate() {
            recent.push(
                div()
                    .py(px(7.0))
                    .flex()
                    .gap(px(12.0))
                    .border_t_1()
                    .border_color(c(t.line[0]))
                    .child(div().w(px(90.0)).text_color(c(t.text[2])).text_size(px(12.0)).child(ago(e.ts)))
                    .child(div().flex_1().truncate().child(wording::printable(&e.summary)))
                    .when(i == 0, |el| el),
            );
        }
        let open_timeline = button(t, "open-timeline", "Open the timeline", false).on_click(cx.listener(
            |this, _: &ClickEvent, _w, cx| {
                this.set_tab(8, 0);
                cx.notify();
            },
        ));
        let events = self
            .rise(7, card(t).p(px(16.0)).gap(px(4.0)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(card_title(t, "What Vigil noticed"))
                    .child(div().flex_1())
                    .child(open_timeline),
            )
            .children(recent);

        div()
            .flex()
            .flex_col()
            .gap(px(14.0))
            .child(
                self.rise(0, div().flex().flex_col().gap(px(4.0)))
                    .child(div().text_size(px(22.0)).child("This PC, right now"))
                    .child(div().text_color(c(t.text[2])).child(format!(
                        "Seen by the daemon as {}, updated {}.",
                        d.procs.viewer.user,
                        self.last_update.map_or("never".into(), |u| if u.elapsed().as_secs() < 3 {
                            "just now".into()
                        } else {
                            format!("{} s ago", u.elapsed().as_secs())
                        })
                    ))),
            )
            .child(tiles)
            .child(div().flex().flex_wrap().gap(px(14.0)).child(talking).child(seeing))
            .child(events)
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

    fn network_map(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = self.theme.clone();
        let Some(d) = &self.data else { return div().into_any_element() };
        let reduced = self.reduced();
        let bounds_cell = self.map_bounds.clone();
        let layout_w = |b: gpui::Bounds<gpui::Pixels>| (f32::from(b.size.width), f32::from(b.size.height));
        // Everything the painter needs, owned.
        let progs_count = real_connections(d).count();
        let snapshot_layout = {
            let (w, h) = bounds_cell.get().map_or((900.0, 560.0), layout_w);
            map_layout(d, w, h)
        };
        let sel_key = match &self.sel {
            Some(Sel::Program(k)) => Some(k.clone()),
            _ => None,
        };
        let start = self.started;
        let cell = bounds_cell.clone();
        let painter = canvas(
            move |b, _, _| {
                cell.set(Some(b));
            },
            move |b, _, w, cx| {
                let (bw, bh) = (f32::from(b.size.width), f32::from(b.size.height));
                let lay = &snapshot_layout;
                let o = point(b.origin.x + px(bw / 2.0), b.origin.y + px(bh / 2.0));
                let at = |x: f32, y: f32| point(o.x + px(x), o.y + px(y));
                // Faint spokes from this PC to each program.
                let mut spokes = PathBuilder::stroke(px(1.0));
                for p in &lay.progs {
                    spokes.move_to(at(0.0, 0.0));
                    spokes.line_to(at(p.x, p.y));
                }
                if let Ok(path) = spokes.build() {
                    w.paint_path(path, ca(t.line[2], 0.6));
                }
                // Program to destination edges; live ones brighter.
                for live in [false, true] {
                    let mut e = PathBuilder::stroke(px(if live { 1.2 } else { 1.0 }));
                    let mut any = false;
                    for (pi, di, _, l) in &lay.edges {
                        if *l != live {
                            continue;
                        }
                        any = true;
                        e.move_to(at(lay.progs[*pi].x, lay.progs[*pi].y));
                        e.line_to(at(lay.dests[*di].x, lay.dests[*di].y));
                    }
                    if any {
                        if let Ok(path) = e.build() {
                            w.paint_path(path, ca(t.live, if live { 0.45 } else { 0.18 }));
                        }
                    }
                }
                // Particles flow along open connections: outward for outbound, inward for inbound.
                if !reduced {
                    let secs = start.elapsed().as_secs_f32();
                    for (k, (pi, di, inbound, live)) in lay.edges.iter().enumerate() {
                        if !live {
                            continue;
                        }
                        let (p, q) = (&lay.progs[*pi], &lay.dests[*di]);
                        let len = ((q.x - p.x).powi(2) + (q.y - p.y).powi(2)).sqrt().max(1.0);
                        for j in 0..2 {
                            let mut f = (secs * 70.0 / len + k as f32 * 0.37 + j as f32 * 0.5).fract();
                            if *inbound {
                                f = 1.0 - f;
                            }
                            let (x, y) = (p.x + (q.x - p.x) * f, p.y + (q.y - p.y) * f);
                            let a = (f * PI).sin();
                            w.paint_quad(
                                gpui::fill(
                                    gpui::Bounds::new(at(x - 1.6, y - 1.6), gpui::size(px(3.2), px(3.2))),
                                    ca(t.live_hi, a),
                                )
                                .corner_radii(px(1.6)),
                            );
                        }
                    }
                }
                let font = w.text_style().font();
                let label = |w: &mut gpui::Window,
                             cx: &mut gpui::App,
                             text: &str,
                             x: f32,
                             y: f32,
                             col: gpui::Hsla,
                             size: f32| {
                    let run = TextRun {
                        len: text.len(),
                        font: font.clone(),
                        color: col,
                        background_color: None,
                        underline: None,
                        strikethrough: None,
                    };
                    let line = w.text_system().shape_line(SharedString::from(text.to_string()), px(size), &[run], None);
                    let _ = line.paint(at(x, y), px(size + 4.0), TextAlign::Left, None, w, cx);
                };
                // Destinations.
                for (i, q) in lay.dests.iter().enumerate() {
                    let r = 3.0 + (q.count as f32).sqrt();
                    w.paint_quad(
                        gpui::fill(
                            gpui::Bounds::new(at(q.x - r, q.y - r), gpui::size(px(2.0 * r), px(2.0 * r))),
                            c(t.live),
                        )
                        .corner_radii(px(r)),
                    );
                    if i < 36 {
                        let right = q.x >= 0.0;
                        let tw = q.label.len() as f32 * 5.6;
                        label(
                            w,
                            cx,
                            &q.label,
                            if right { q.x + r + 5.0 } else { q.x - r - 5.0 - tw },
                            q.y - 7.0,
                            ca(t.text[2], 1.0),
                            10.5,
                        );
                    }
                }
                // Programs, with a halo on the selected one.
                for p in &lay.progs {
                    let hidden = p.key.starts_with("hidden:");
                    let r = 5.0 + (p.count as f32).sqrt() * 1.6;
                    if sel_key.as_deref() == Some(p.key.as_str()) {
                        let hr = r + 6.0;
                        w.paint_quad(gpui::quad(
                            gpui::Bounds::new(at(p.x - hr, p.y - hr), gpui::size(px(2.0 * hr), px(2.0 * hr))),
                            px(hr),
                            gpui::Hsla::transparent_black(),
                            px(1.5),
                            c(t.accent),
                            gpui::BorderStyle::Solid,
                        ));
                    }
                    let col = if hidden { ca(t.text[2], 1.0) } else { c(t.accent) };
                    w.paint_quad(
                        gpui::fill(gpui::Bounds::new(at(p.x - r, p.y - r), gpui::size(px(2.0 * r), px(2.0 * r))), col)
                            .corner_radii(px(r)),
                    );
                    let right = p.x >= -1.0;
                    let tw = p.label.len() as f32 * 6.6;
                    label(
                        w,
                        cx,
                        &p.label,
                        if right { p.x + r + 7.0 } else { p.x - r - 7.0 - tw },
                        p.y - 8.0,
                        c(t.text[0]),
                        12.0,
                    );
                }
                // This PC: the mark, at the centre.
                mark::paint(w, o, &MarkFrame::at_rest(0.0, 0.0, 14.0));
            },
        )
        .size_full();
        let legend = div()
            .flex()
            .gap(px(18.0))
            .text_size(px(12.0))
            .text_color(c(self.theme.text[2]))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(div().size(px(9.0)).rounded_full().bg(c(self.theme.accent)))
                    .child("program"),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(div().size(px(8.0)).rounded_full().bg(c(self.theme.live)))
                    .child("address it talks to"),
            )
            .child(div().child("moving dots: open now, in the direction the connection was made"))
            .child(div().flex_1())
            .child(format!("{progs_count} connections · click a program"));
        let mapbox = div()
            .id("map")
            .h(px(560.0))
            .w_full()
            .rounded(px(self.theme.radius))
            .bg(c(self.theme.bg[1]))
            .border_1()
            .border_color(c(self.theme.line[0]))
            .overflow_hidden()
            .child(painter)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, ev: &MouseDownEvent, _w, cx| {
                    let (Some(b), Some(d)) = (this.map_bounds.get(), this.data.as_ref()) else { return };
                    let (bw, bh) = (f32::from(b.size.width), f32::from(b.size.height));
                    let lay = map_layout(d, bw, bh);
                    let (mx, my) = (
                        f32::from(ev.position.x - b.origin.x) - bw / 2.0,
                        f32::from(ev.position.y - b.origin.y) - bh / 2.0,
                    );
                    let hit = lay.progs.iter().filter(|p| !p.key.starts_with("hidden:")).min_by(|a, b| {
                        let da = (a.x - mx).powi(2) + (a.y - my).powi(2);
                        let db = (b.x - mx).powi(2) + (b.y - my).powi(2);
                        da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
                    });
                    match hit {
                        Some(p) if (p.x - mx).powi(2) + (p.y - my).powi(2) < 26.0 * 26.0 => {
                            this.sel = Some(Sel::Program(p.key.clone()))
                        }
                        _ => this.sel = None,
                    }
                    cx.notify();
                }),
            );
        div().flex().flex_col().gap(px(12.0)).child(mapbox).child(legend).into_any_element()
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
        let mut cols = vec![("Program", 0.0), ("Address", 280.0), ("Where", 90.0), ("State", 110.0)];
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
            let state_col = if s.state == "ESTABLISHED" { t.ok } else { t.text[2] };
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
                            div()
                                .text_color(if s.direction == "in" { c(t.warn) } else { c(t.text[2]) })
                                .child(if s.direction == "in" { "↙" } else { "↗" }),
                        )
                        .child(
                            div()
                                .truncate()
                                .text_color(if s.program.is_some() { c(t.text[0]) } else { c(t.text[2]) })
                                .child(name),
                        ),
                )
                .child(div().w(px(280.0)).truncate().child(endpoint(&s.remote_ip, s.remote_port)))
                .child(div().w(px(90.0)).text_color(c(t.text[2])).child(scope_of(&s.remote_ip)))
                .child(div().w(px(110.0)).child(chip(s.state.clone(), state_col)));
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
                this.sel = key.clone().map(Sel::Program);
                cx.notify();
            }));
            rows.push(row_enter(row, id2("conn-in", self.nav, i as u64), i, reduced).into_any_element());
        }
        let n = socks.len();
        div()
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
            .child(card(t).p(px(10.0)).child(head(&cols)).children(rows).when(n == 0, |el| {
                el.child(div().p(px(12.0)).text_color(c(t.text[2])).child("No connection matches."))
            }))
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

    fn processes(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = &self.theme;
        let Some(d) = &self.data else { return div().into_any_element() };
        let tree = self.tab[2] == 0;
        let expert = self.settings.view(AREAS[2].id) == View::Expert;
        let reduced = self.reduced();
        let by_pid: HashMap<u32, &ProcessInfo> = d.procs.processes.iter().map(|p| (p.pid, p)).collect();
        let order: Vec<(u32, usize)> =
            if tree { tree_order(&d.procs.processes) } else { d.procs.processes.iter().map(|p| (p.pid, 0)).collect() };
        let sockets_per_pid: HashMap<u32, usize> =
            d.net.sockets.iter().filter(|s| s.kind == "connection").flat_map(|s| s.pids.clone()).fold(
                HashMap::new(),
                |mut m, p| {
                    *m.entry(p).or_insert(0) += 1;
                    m
                },
            );
        let mut rows = vec![];
        let mut shown = 0;
        for (pid, depth) in order {
            let Some(p) = by_pid.get(&pid) else { continue };
            if !matches_filter(p, &self.filter) {
                continue;
            }
            let i = shown;
            shown += 1;
            if shown > 600 {
                continue;
            }
            let selected = self.sel == Some(Sel::Proc(pid));
            let net = sockets_per_pid.get(&pid).copied().unwrap_or(0);
            let indent = if tree && self.filter.is_empty() { depth.min(12) as f32 * 16.0 } else { 0.0 };
            let mut row = div()
                .id(id2("proc", self.nav, pid as u64))
                .h(px(32.0))
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
                        .min_w(px(0.0))
                        .flex()
                        .items_center()
                        .gap(px(8.0))
                        .pl(px(indent))
                        .when(indent > 0.0, |el| el.child(div().w(px(8.0)).h(px(1.0)).bg(c(t.line[2]))))
                        .child(div().truncate().child(wording::printable(&p.name)))
                        .when(p.exe_deleted, |el| el.child(chip("deleted file", t.warn)))
                        .when(net > 0, |el| el.child(chip(format!("{net} net"), t.live))),
                )
                .child(div().w(px(70.0)).text_color(c(t.text[2])).child(p.pid.to_string()))
                .child(div().w(px(110.0)).truncate().text_color(c(t.text[2])).child(p.user.clone()))
                .child(div().w(px(110.0)).text_color(c(t.text[2])).child(p.started.map_or("-".into(), ago)));
            if expert {
                row = row.child(
                    div()
                        .w(px(360.0))
                        .truncate()
                        .text_color(c(t.text[2]))
                        .child(wording::printable(&p.cmdline.join(" "))),
                );
            }
            let row = row.on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                this.sel = if this.sel == Some(Sel::Proc(pid)) { None } else { Some(Sel::Proc(pid)) };
                cx.notify();
            }));
            rows.push(row_enter(row, id2("proc-in", self.nav, i as u64), i, reduced).into_any_element());
        }
        let hidden: usize = d.procs.unreadable_by_uid.values().sum();
        let note = if hidden > 0 {
            format!("{shown} processes · {hidden} belong to other users or are protected, so their details are limited (the installed daemon sees everything)")
        } else {
            format!("{shown} processes")
        };
        let mut head = div()
            .flex()
            .px(px(10.0))
            .pb(px(6.0))
            .text_size(px(11.5))
            .text_color(c(t.text[2]))
            .child(div().flex_1().child("Program"))
            .child(div().w(px(70.0)).child("PID"))
            .child(div().w(px(110.0)).child("User"))
            .child(div().w(px(110.0)).child("Started"));
        if expert {
            head = head.child(div().w(px(360.0)).child("Command line"));
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.0))
                    .child(div().w(px(420.0)).child(self.filter_box("Filter by name, user, pid or command line", cx)))
                    .child(div().text_color(c(t.text[2])).text_size(px(12.0)).child(note)),
            )
            .child(card(t).p(px(10.0)).child(head).children(rows))
            .into_any_element()
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
            .p(px(16.0))
            .child(card_title(t, "Everything Vigil noticed or did, newest first"))
            .children(rows)
            .when(d.events.is_empty(), |el| el.child(div().pt(px(8.0)).text_color(c(t.text[2])).child("Nothing yet.")))
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

    fn detail(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let d = self.data.as_ref()?;
        let sel = self.sel.clone()?;
        let t = &self.theme;
        let key_n = match &sel {
            Sel::Proc(p) => *p as u64,
            Sel::Program(k) => hash01(k).to_bits() as u64,
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
                    .child(div().text_size(px(19.0)).child(program_name(d, key)))
                    .child(
                        div()
                            .pt(px(6.0))
                            .flex()
                            .gap(px(6.0))
                            .child(chip(
                                format!("{} connections", socks.iter().filter(|s| s.kind == "connection").count()),
                                t.live,
                            ))
                            .child(chip(format!("{} addresses", addrs.len()), t.text[1])),
                    )
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
                            .child(chip(s.state.clone(), if s.state == "ESTABLISHED" { t.ok } else { t.text[2] }))
                    }))
            }
        };
        let panel = div()
            .id(id("detail", key_n))
            .w(px(DETAIL_W))
            .h_full()
            .flex_none()
            .bg(c(t.bg[1]))
            .border_l_1()
            .border_color(c(t.line[1]))
            .overflow_y_scroll()
            .p(px(20.0))
            .child(div().flex().justify_end().child(close))
            .child(body);
        Some(slide_in(panel, id("detail-in", key_n), self.reduced()).into_any_element())
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
        }
    }

    #[test]
    fn tree_order_nests_children_under_parents() {
        let procs = vec![p(1, 0), p(5, 1), p(7, 5), p(3, 1), p(9, 42)];
        assert_eq!(tree_order(&procs), vec![(1, 0), (3, 1), (5, 1), (7, 2), (9, 0)]);
    }
}
