//! The network map: who this PC is talking to, all on one screen, nothing overlapping.
//!
//! This PC sits in the centre. The programs holding connections sit on an arc around it,
//! split between its left and right so the load is even, and the addresses each program
//! talks to stand in a column on that program's side, in the same top-to-bottom order so
//! links rarely cross. Links are smooth curves: teal for open connections, amber for
//! connections made *to* this PC, grey for ones closing. Nothing moves.
//!
//! Clicking a program or an address highlights its links and fills the inspector beside
//! the map (the map never resizes and nothing covers it); clicking it again clears it.
//! Clicking a program also flags its window in the taskbar, where the desktop allows it.
//! The background is a quiet hexagon grid, a still starfield or plain (Settings).

use gpui::{canvas, div, point, prelude::*, px, AnyElement, ClickEvent, Context, PathBuilder};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use vigil_model::host::{NetSnapshot, Socket};
use vigil_model::netaddr::scope_of;
use vigil_model::wording;
use vigil_ui_core::theme::Rgba;

use crate::ui::{c, ca, id, id2};
use crate::views::{program_name_in, real_connections_in, service_name};
use crate::{live, mark, Sel, Vigil};

pub const PROG_H: f32 = 32.0;
pub const DEST_H: f32 = 24.0;
const MARGIN: f32 = 18.0;
const TOP: f32 = 18.0;
const BOTTOM: f32 = 40.0;
/// The PC node's radius.
const PC_R: f32 = 30.0;

pub struct ProgNode {
    pub key: String,
    pub label: String,
    pub count: usize,
    pub x: f32,
    pub y: f32,
    pub right: bool,
    pub hidden: bool,
}

pub struct DestNode {
    pub ip: String,
    pub service: String,
    pub scope: &'static str,
    pub x: f32,
    pub y: f32,
    pub right: bool,
    /// "+N more" for a program whose addresses did not all fit.
    pub more: Option<(usize, usize)>,
}

pub struct Edge {
    pub prog: usize,
    pub dest: usize,
    pub inbound: bool,
    pub open: bool,
}

/// A curve to draw: points, colour (0xRRGGBB), alpha, width.
type Stroke = (Vec<(f32, f32)>, u32, f32, f32);

pub struct MapGeo {
    pub pc: (f32, f32),
    pub progs: Vec<ProgNode>,
    pub dests: Vec<DestNode>,
    pub edges: Vec<Edge>,
    pub prog_w: f32,
    pub dest_w: f32,
}

fn hidden_label(reason: &str) -> String {
    match reason {
        "other-user" => "Other users (hidden)".into(),
        "closed" => "Closing".into(),
        "protected" => "Protected (hidden)".into(),
        _ => "Unattributed".into(),
    }
}

/// `n` positions spaced at most `step` apart, centred on `mid`, within `span`.
fn spread(n: usize, mid: f32, span: f32, step: f32) -> Vec<f32> {
    let gap = (span / n.max(1) as f32).min(step);
    let first = mid - gap * (n as f32 - 1.0) / 2.0;
    (0..n).map(|i| first + gap * i as f32).collect()
}

/// Where everything goes in a `w` x `h` map (pixels, from the map's top-left corner).
pub fn geometry(net: &NetSnapshot, w: f32, h: f32) -> MapGeo {
    let mut per: BTreeMap<String, Vec<&Socket>> = BTreeMap::new();
    for s in real_connections_in(net) {
        let key = s
            .program
            .clone()
            .unwrap_or_else(|| format!("hidden:{}", s.hidden.as_ref().map_or("unknown", |h| h.reason.as_str())));
        per.entry(key).or_default().push(s);
    }
    let mut ranked: Vec<(String, Vec<&Socket>)> = per.into_iter().collect();
    ranked.sort_by(|a, b| {
        a.0.starts_with("hidden:").cmp(&b.0.starts_with("hidden:")).then(b.1.len().cmp(&a.1.len())).then(a.0.cmp(&b.0))
    });
    let usable = (h - TOP - BOTTOM).max(80.0);
    let (cx, cy) = (w / 2.0, TOP + usable / 2.0);
    // Widths shrink together on narrow windows so both sides always fit.
    let half = w / 2.0 - MARGIN;
    let k = ((half - PC_R - 100.0) / (176.0 + 196.0)).clamp(0.55, 1.0);
    let (prog_w, dest_w) = (176.0 * k, 196.0 * k);
    let per_side = ((usable / (PROG_H + 12.0)).floor() as usize).max(1);
    ranked.truncate(per_side * 2);
    // Addresses per program, busiest first.
    let uniq: Vec<Vec<String>> = ranked
        .iter()
        .map(|(_, socks)| {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for s in socks {
                *counts.entry(s.remote_ip.as_str()).or_insert(0) += 1;
            }
            let mut v: Vec<(&str, usize)> = counts.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            v.into_iter().map(|(ip, _)| ip.to_string()).collect()
        })
        .collect();
    // Sides: each program goes where fewer addresses are already shown (right on a tie).
    let mut side_load = [0usize; 2];
    let mut side_of = vec![true; ranked.len()];
    let mut side_progs: [Vec<usize>; 2] = [vec![], vec![]];
    for (i, ips) in uniq.iter().enumerate() {
        let right = side_load[1] <= side_load[0] && side_progs[1].len() < per_side || side_progs[0].len() >= per_side;
        let s = usize::from(right);
        side_of[i] = right;
        side_load[s] += ips.len().max(1);
        side_progs[s].push(i);
    }
    // Programs on an arc around the PC: further out at mid height, closer at the top and
    // bottom, like points on an ellipse.
    let dest_inner = half - dest_w; // distance from the centre to a column's inner edge
    let reach = (dest_inner - 56.0 - prog_w).max(PC_R + 24.0);
    let mut progs: Vec<ProgNode> = Vec::with_capacity(ranked.len());
    let mut prog_y = vec![0.0f32; ranked.len()];
    for list in &side_progs {
        let ys = spread(list.len(), cy, usable - PROG_H, 72.0);
        for (&i, y) in list.iter().zip(ys) {
            prog_y[i] = y;
        }
    }
    for (i, (key, socks)) in ranked.iter().enumerate() {
        let hidden = key.starts_with("hidden:");
        let y = prog_y[i];
        let dy = ((y - cy) / (usable / 2.0)).clamp(-1.0, 1.0);
        let off = (PC_R + 24.0).max(reach * (1.0 - dy * dy).sqrt());
        let right = side_of[i];
        let x = if right { cx + off } else { cx - off - prog_w };
        progs.push(ProgNode {
            key: key.clone(),
            label: if hidden { hidden_label(&key[7..]) } else { program_name_in(net, key) },
            count: socks.len(),
            x,
            y: y - PROG_H / 2.0,
            right,
            hidden,
        });
    }
    // Address columns, one per side, in the order of their programs.
    let slots = ((usable / (DEST_H + 6.0)).floor() as usize).max(1);
    let mut dests = vec![];
    let mut index: HashMap<(usize, String), usize> = HashMap::new();
    let mut more_of: HashMap<usize, usize> = HashMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (s, list) in side_progs.iter().enumerate() {
        let mut order: Vec<usize> = list.clone();
        order.sort_by(|a, b| prog_y[*a].partial_cmp(&prog_y[*b]).unwrap_or(std::cmp::Ordering::Equal));
        let total: usize = order.iter().map(|i| uniq[*i].len()).sum::<usize>().max(1);
        let mut placed: Vec<(usize, String, Option<usize>)> = vec![];
        for &pi in &order {
            let fresh: Vec<&String> = uniq[pi].iter().filter(|ip| !seen.contains(*ip)).collect();
            let share = ((slots as f32 * uniq[pi].len() as f32 / total as f32).floor() as usize).max(1);
            let fits = fresh.len() <= share;
            let show = if fits { fresh.len() } else { share.saturating_sub(1).max(1) };
            for ip in fresh.iter().take(show) {
                seen.insert((*ip).clone());
                placed.push((pi, (*ip).clone(), None));
            }
            if !fits {
                placed.push((pi, String::new(), Some(fresh.len() - show)));
            }
        }
        let right = s == 1;
        let x = if right { w - MARGIN - dest_w } else { MARGIN };
        let ys = spread(placed.len(), cy, usable - DEST_H, DEST_H + 10.0);
        for ((pi, ip, more), y) in placed.into_iter().zip(ys) {
            let y = y - DEST_H / 2.0;
            match more {
                Some(n) => {
                    more_of.insert(pi, dests.len());
                    dests.push(DestNode {
                        ip: String::new(),
                        service: String::new(),
                        scope: "",
                        x,
                        y,
                        right,
                        more: Some((pi, n)),
                    });
                }
                None => {
                    let sock = ranked[pi].1.iter().find(|s| s.remote_ip == ip);
                    let service = sock.map_or(String::new(), |s| {
                        service_name(&s.proto, if s.direction == "in" { s.local_port } else { s.remote_port })
                    });
                    index.insert((s, ip.clone()), dests.len());
                    dests.push(DestNode { scope: scope_of(&ip), ip, service, x, y, right, more: None });
                }
            }
        }
    }
    let mut edges = vec![];
    let mut done = BTreeSet::new();
    for (pi, (_, socks)) in ranked.iter().enumerate() {
        let s = usize::from(side_of[pi]);
        for sock in socks {
            let di = index
                .get(&(s, sock.remote_ip.clone()))
                .or_else(|| index.get(&(1 - s, sock.remote_ip.clone())))
                .copied()
                .or_else(|| more_of.get(&pi).copied());
            if let Some(di) = di {
                if done.insert((pi, di)) {
                    let all: Vec<&&Socket> = socks.iter().filter(|x| x.remote_ip == sock.remote_ip).collect();
                    edges.push(Edge {
                        prog: pi,
                        dest: di,
                        inbound: all.iter().any(|x| x.direction == "in"),
                        open: all.iter().any(|x| x.state == "ESTABLISHED"),
                    });
                }
            }
        }
    }
    MapGeo { pc: (cx, cy), progs, dests, edges, prog_w, dest_w }
}

/// Points along a smooth S-curve from `a` to `b` (horizontal tangents at both ends).
fn curve(a: (f32, f32), b: (f32, f32)) -> Vec<(f32, f32)> {
    let dx = (b.0 - a.0) * 0.5;
    (0..=24)
        .map(|i| {
            let t = i as f32 / 24.0;
            let u = 1.0 - t;
            let (c1, c2) = ((a.0 + dx, a.1), (b.0 - dx, b.1));
            (
                u * u * u * a.0 + 3.0 * u * u * t * c1.0 + 3.0 * u * t * t * c2.0 + t * t * t * b.0,
                u * u * u * a.1 + 3.0 * u * u * t * c1.1 + 3.0 * u * t * t * c2.1 + t * t * t * b.1,
            )
        })
        .collect()
}

/// Vigil 1's "Grid" background: a tile of five hexagons and a few small shapes, 112 x 97.
fn paint_grid(w: &mut gpui::Window, o: gpui::Point<gpui::Pixels>, bw: f32, bh: f32, line: u32, live: u32) {
    let hex = |cx: f32, cy: f32, r: f32| -> Vec<(f32, f32)> {
        (0..=6)
            .map(|i| {
                let a = std::f32::consts::PI / 3.0 * i as f32 + std::f32::consts::PI / 6.0;
                (cx + r * a.cos(), cy + r * a.sin())
            })
            .collect()
    };
    let centres = [(28.0, 24.0), (84.0, 24.0), (0.0, 72.5), (56.0, 72.5), (112.0, 72.5)];
    let mut hexes = PathBuilder::stroke(px(1.0));
    let mut shapes = PathBuilder::stroke(px(1.0));
    let mut ty = 0.0;
    while ty < bh + 97.0 {
        let mut tx = 0.0;
        while tx < bw + 112.0 {
            for (hx, hy) in centres {
                let pts = hex(tx + hx, ty + hy, 16.0);
                hexes.move_to(point(o.x + px(pts[0].0), o.y + px(pts[0].1)));
                for p in &pts[1..] {
                    hexes.line_to(point(o.x + px(p.0), o.y + px(p.1)));
                }
            }
            // A small triangle and a plus, as in the original tile.
            let at = |x: f32, y: f32| point(o.x + px(tx + x), o.y + px(ty + y));
            shapes.move_to(at(56.0, 4.0));
            shapes.line_to(at(60.0, 11.0));
            shapes.line_to(at(52.0, 11.0));
            shapes.line_to(at(56.0, 4.0));
            shapes.move_to(at(24.0, 56.0));
            shapes.line_to(at(24.0, 62.0));
            shapes.move_to(at(21.0, 59.0));
            shapes.line_to(at(27.0, 59.0));
            tx += 112.0;
        }
        ty += 97.0;
    }
    if let Ok(p) = hexes.build() {
        w.paint_path(p, mark::hsla(line, 0.075));
    }
    if let Ok(p) = shapes.build() {
        w.paint_path(p, mark::hsla(live, 0.11));
    }
}

/// "Night": a still field of stars, the same every time (placed by a hash, not at random).
fn paint_stars(w: &mut gpui::Window, o: gpui::Point<gpui::Pixels>, bw: f32, bh: f32) {
    let mut h: u32 = 0x9e37_79b9;
    let mut next = || {
        h ^= h << 13;
        h ^= h >> 17;
        h ^= h << 5;
        (h % 10_000) as f32 / 10_000.0
    };
    let n = ((bw * bh) / 2600.0) as usize;
    for _ in 0..n {
        let (x, y, r, a) = (next() * bw, next() * bh, 0.5 + next() * 0.9, 0.12 + next() * 0.4);
        w.paint_quad(
            gpui::fill(
                gpui::Bounds::new(point(o.x + px(x - r), o.y + px(y - r)), gpui::size(px(2.0 * r), px(2.0 * r))),
                mark::hsla(0xdde8ff, a),
            )
            .corner_radii(px(r)),
        );
    }
}

impl Vigil {
    pub fn network_map(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = self.theme.clone();
        let Some(d) = &self.data else { return div().into_any_element() };
        let (w, h) =
            self.map_bounds.get().map_or((1100.0, 640.0), |b| (f32::from(b.size.width), f32::from(b.size.height)));
        let geo = geometry(&d.net, w, h);
        let (pw, dw) = (geo.prog_w, geo.dest_w);
        let sel_prog = match &self.sel {
            Some(Sel::Program(k)) => geo.progs.iter().position(|p| &p.key == k),
            _ => None,
        };
        let sel_dest = match &self.sel {
            Some(Sel::Addr(ip)) => geo.dests.iter().position(|x| &x.ip == ip),
            _ => None,
        };
        let any_sel = sel_prog.is_some() || sel_dest.is_some();
        let lit_prog =
            |i: usize| sel_prog == Some(i) || geo.edges.iter().any(|e| e.prog == i && sel_dest == Some(e.dest));
        let lines: Vec<Stroke> = {
            let mut v = vec![];
            for (i, p) in geo.progs.iter().enumerate() {
                let on = lit_prog(i);
                let inner = if p.right { (p.x, p.y + PROG_H / 2.0) } else { (p.x + pw, p.y + PROG_H / 2.0) };
                let from = (geo.pc.0 + if p.right { PC_R } else { -PC_R }, geo.pc.1);
                v.push((
                    curve(from, inner),
                    if on { t.accent.0 >> 8 } else { t.text[2].0 >> 8 },
                    if any_sel && !on {
                        0.12
                    } else if on {
                        0.9
                    } else {
                        0.4
                    },
                    if on { 1.6 } else { 1.0 },
                ));
            }
            for e in &geo.edges {
                let (p, q) = (&geo.progs[e.prog], &geo.dests[e.dest]);
                let on = sel_prog == Some(e.prog) || sel_dest == Some(e.dest);
                let colour = if on {
                    t.accent
                } else if e.inbound {
                    t.warn
                } else if e.open {
                    t.live
                } else {
                    t.text[2]
                };
                let alpha = if any_sel && !on {
                    0.08
                } else if on {
                    0.95
                } else {
                    0.45
                };
                let a = if p.right { (p.x + pw, p.y + PROG_H / 2.0) } else { (p.x, p.y + PROG_H / 2.0) };
                let b = if q.right { (q.x, q.y + DEST_H / 2.0) } else { (q.x + dw, q.y + DEST_H / 2.0) };
                v.push((curve(a, b), colour.0 >> 8, alpha, if on { 1.6 } else { 1.1 }));
            }
            v
        };
        let background = self.settings.map_background.clone();
        let (line, live) = (t.line[2].0 >> 8, t.live.0 >> 8);
        let cell = self.map_bounds.clone();
        let painter = canvas(
            move |b, w, _| {
                if cell.get() != Some(b) {
                    cell.set(Some(b));
                    w.refresh();
                }
            },
            move |b, _, w, _| {
                let o = b.origin;
                let (bw, bh) = (f32::from(b.size.width), f32::from(b.size.height));
                match background.as_str() {
                    "night" => paint_stars(w, o, bw, bh),
                    "plain" => {}
                    _ => paint_grid(w, o, bw, bh, line, live),
                }
                for (pts, colour, alpha, width) in &lines {
                    let mut p = PathBuilder::stroke(px(*width));
                    p.move_to(point(o.x + px(pts[0].0), o.y + px(pts[0].1)));
                    for q in &pts[1..] {
                        p.line_to(point(o.x + px(q.0), o.y + px(q.1)));
                    }
                    if let Ok(path) = p.build() {
                        w.paint_path(path, mark::hsla(*colour, *alpha));
                    }
                }
            },
        )
        .absolute()
        .top_0()
        .left_0()
        .size_full();

        let pc = geo.pc;
        let kind_icon = match self.device.kind {
            vigil_sensor::device::Kind::Laptop => "laptop",
            _ => "desktop",
        };
        let mut nodes: Vec<AnyElement> = vec![
            div()
                .absolute()
                .left(px(pc.0 - PC_R))
                .top(px(pc.1 - PC_R))
                .size(px(PC_R * 2.0))
                .rounded_full()
                .bg(c(t.bg[3]))
                .border_1()
                .border_color(c(t.line[2]))
                .flex()
                .items_center()
                .justify_center()
                .child(gpui::svg().path(format!("icons/{kind_icon}.svg")).size(px(26.0)).text_color(c(t.text[0])))
                .into_any_element(),
            div()
                .absolute()
                .left(px(pc.0 - 90.0))
                .top(px(pc.1 + PC_R + 6.0))
                .w(px(180.0))
                .flex()
                .justify_center()
                .text_size(px(12.0))
                .text_color(c(t.text[1]))
                .child(div().truncate().child(wording::printable(&self.device.name)))
                .into_any_element(),
        ];
        for (i, p) in geo.progs.iter().enumerate() {
            let on = sel_prog == Some(i);
            let lit = lit_prog(i);
            let key = p.key.clone();
            let hidden = p.hidden;
            let pids: Vec<u32> = d
                .net
                .sockets
                .iter()
                .filter(|s| s.program.as_deref() == Some(p.key.as_str()))
                .flat_map(|s| s.pids.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let icon = self.icons.as_ref().and_then(|i| i.for_exe(&p.key)).map(|p| p.to_string_lossy().into_owned());
            let name = p.label.clone();
            nodes.push(
                div()
                    .id(id2("mprog", self.nav, i as u64))
                    .absolute()
                    .left(px(p.x))
                    .top(px(p.y))
                    .w(px(pw))
                    .h(px(PROG_H))
                    .pl(px(6.0))
                    .pr(px(8.0))
                    .flex()
                    .items_center()
                    .gap(px(8.0))
                    .rounded(px(PROG_H / 2.0))
                    .bg(if on { c(t.accent_soft) } else { c(t.bg[2]) })
                    .border_1()
                    .border_color(if lit { c(t.accent) } else { c(t.line[1]) })
                    .when(any_sel && !lit, |el| el.opacity(0.5))
                    .cursor_pointer()
                    .hover(|s| s.border_color(ca(Rgba(0xffffff40), 1.0)))
                    .child(if hidden {
                        div()
                            .size(px(20.0))
                            .flex_none()
                            .rounded_full()
                            .bg(c(t.bg[4]))
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(gpui::svg().path("icons/eye.svg").size(px(12.0)).text_color(c(t.text[2])))
                            .into_any_element()
                    } else {
                        self.app_icon(&p.key, 20.0)
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .truncate()
                            .text_size(px(12.5))
                            .text_color(if hidden { c(t.text[2]) } else { c(t.text[0]) })
                            .child(p.label.clone()),
                    )
                    .child(
                        div()
                            .flex_none()
                            .px(px(6.0))
                            .rounded(px(8.0))
                            .bg(c(t.bg[4]))
                            .text_size(px(11.0))
                            .text_color(c(t.text[1]))
                            .child(p.count.to_string()),
                    )
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        if this.sel == Some(Sel::Program(key.clone())) {
                            this.sel = None;
                        } else if !hidden {
                            this.sel = Some(Sel::Program(key.clone()));
                            let _ = this.req.send(live::Req::Attention {
                                pids: pids.clone(),
                                name: name.clone(),
                                icon: icon.clone(),
                            });
                        }
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        for (i, q) in geo.dests.iter().enumerate() {
            let on = sel_dest == Some(i) || geo.edges.iter().any(|e| e.dest == i && sel_prog == Some(e.prog));
            let base = div()
                .id(id2("mdest", self.nav, i as u64))
                .absolute()
                .left(px(q.x))
                .top(px(q.y))
                .w(px(dw))
                .h(px(DEST_H))
                .px(px(9.0))
                .flex()
                .items_center()
                .gap(px(7.0))
                .rounded(px(6.0))
                .bg(if sel_dest == Some(i) { c(t.accent_soft) } else { c(t.bg[1]) })
                .border_1()
                .border_color(if on { c(t.accent) } else { c(t.line[0]) })
                .when(any_sel && !on, |el| el.opacity(0.45))
                .cursor_pointer()
                .hover(|s| s.border_color(ca(Rgba(0xffffff40), 1.0)))
                .text_size(px(12.0));
            let el = match q.more {
                Some((pi, n)) => {
                    let key = geo.progs[pi].key.clone();
                    base.child(div().text_color(c(t.text[2])).child(format!("+{n} more"))).on_click(cx.listener(
                        move |this, _: &ClickEvent, _w, cx| {
                            this.set_tab(1, 1);
                            this.sel = Some(Sel::Program(key.clone()));
                            cx.notify();
                        },
                    ))
                }
                None => {
                    let ip = q.ip.clone();
                    let lan = matches!(q.scope, "lan" | "link-local");
                    base.child(div().size(px(6.0)).flex_none().rounded_full().bg(if lan {
                        c(t.accent)
                    } else {
                        c(t.live)
                    }))
                    .child(div().flex_1().min_w(px(0.0)).truncate().child(q.ip.clone()))
                    .child(div().flex_none().text_size(px(10.5)).text_color(c(t.text[2])).child(q.service.clone()))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.sel =
                            if this.sel == Some(Sel::Addr(ip.clone())) { None } else { Some(Sel::Addr(ip.clone())) };
                        cx.notify();
                    }))
                }
            };
            nodes.push(el.into_any_element());
        }
        let key_line = |colour: Rgba, label: &'static str| {
            div().flex().items_center().gap(px(6.0)).child(div().w(px(14.0)).h(px(2.0)).bg(c(colour))).child(label)
        };
        let legend = div()
            .absolute()
            .bottom(px(12.0))
            .left(px(16.0))
            .right(px(16.0))
            .flex()
            .gap(px(16.0))
            .text_size(px(11.5))
            .text_color(c(t.text[2]))
            .child(key_line(t.live, "open, made by this PC"))
            .child(key_line(t.warn, "made to this PC"))
            .child(key_line(t.text[2], "closing"))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(div().size(px(6.0)).rounded_full().bg(c(t.accent)))
                    .child("local network"),
            )
            .child(div().flex_1())
            .child(format!(
                "{} programs · {} addresses",
                geo.progs.len(),
                geo.dests.iter().filter(|q| q.more.is_none()).count()
            ));
        div()
            .id(id("map", self.nav))
            .relative()
            .size_full()
            .min_h(px(420.0))
            .rounded(px(t.radius))
            .bg(c(t.bg[1]))
            .border_1()
            .border_color(c(t.line[0]))
            .overflow_hidden()
            .child(painter)
            .children(nodes)
            .child(legend)
            .when(geo.progs.is_empty(), |el| {
                el.child(
                    div()
                        .absolute()
                        .top(px(pc.1 + PC_R + 30.0))
                        .left_0()
                        .right_0()
                        .flex()
                        .justify_center()
                        .text_color(c(t.text[2]))
                        .child("Nothing on this PC is talking to another machine right now."),
                )
            })
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The synthetic /proc fixture, plus SYNTHETIC extra connections: one program with
    /// `extra` addresses (like a browser), so the layout is tested under load.
    fn net(extra: usize) -> NetSnapshot {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/proc");
        let dst = std::env::temp_dir().join(format!("vigil-map-test-{}-{extra}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst);
        vigil_sensor::procfs::materialise_fixture(&src, &dst).expect("fixture");
        let mut n = vigil_sensor::procfs::ProcRoot::at(&dst).net_snapshot(1_700_000_000.0, 0);
        let _ = std::fs::remove_dir_all(&dst);
        let base = n.sockets.iter().find(|s| s.kind == "connection" && s.program.is_some()).cloned().expect("a socket");
        for i in 0..extra {
            let mut s = base.clone();
            s.remote_ip = format!("198.51.{}.{}", i / 200, i % 200 + 1);
            s.inode = 90_000 + i as u64;
            n.sockets.push(s);
        }
        n
    }

    fn overlaps(a: (f32, f32, f32, f32), b: (f32, f32, f32, f32)) -> bool {
        a.0 < b.0 + b.2 && b.0 < a.0 + a.2 && a.1 < b.1 + b.3 && b.1 < a.1 + a.3
    }

    #[test]
    fn nothing_overlaps_and_everything_is_inside() {
        for extra in [0usize, 18, 80] {
            let n = net(extra);
            for (w, h) in [(1490.0, 980.0), (990.0, 760.0), (820.0, 520.0)] {
                let g = geometry(&n, w, h);
                let mut boxes = vec![(g.pc.0 - PC_R, g.pc.1 - PC_R, 2.0 * PC_R, 2.0 * PC_R)];
                boxes.extend(g.progs.iter().map(|p| (p.x, p.y, g.prog_w, PROG_H)));
                boxes.extend(g.dests.iter().map(|q| (q.x, q.y, g.dest_w, DEST_H)));
                for (i, a) in boxes.iter().enumerate() {
                    assert!(a.0 >= 0.0 && a.1 >= 0.0 && a.0 + a.2 <= w && a.1 + a.3 <= h, "{extra} {w}x{h}: {a:?}");
                    for b in &boxes[i + 1..] {
                        assert!(!overlaps(*a, *b), "{extra} {w}x{h}: {a:?} overlaps {b:?}");
                    }
                }
                // Every program reaches at least one address, and every address a program.
                for (i, _) in g.progs.iter().enumerate() {
                    assert!(g.edges.iter().any(|e| e.prog == i), "program {i} has no link");
                }
                for (i, _) in g.dests.iter().enumerate() {
                    assert!(g.edges.iter().any(|e| e.dest == i), "address {i} has no link");
                }
            }
        }
    }
}
