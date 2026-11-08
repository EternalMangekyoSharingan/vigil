//! The network map: who this PC is talking to, laid out so nothing overlaps.
//!
//! Three columns, left to right: this PC, the programs that hold connections (with their
//! icons), and the addresses they talk to, grouped by program so links rarely cross.
//! Links are smooth curves: teal for open connections, amber for connections made *to*
//! this PC, grey for ones closing. Nothing moves. Clicking a program or an address
//! highlights its links and opens its card on top of the map (the map never resizes);
//! clicking it again closes the card. Clicking a program also flags its window in the
//! taskbar, where the desktop allows it.

use gpui::{canvas, div, point, prelude::*, px, AnimationExt, AnyElement, ClickEvent, Context, PathBuilder};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use vigil_model::host::Socket;
use vigil_model::netaddr::scope_of;
use vigil_model::wording;
use vigil_ui_core::theme::Rgba;

use crate::live::Snapshot;
use crate::ui::{c, ca, id, id2};
use crate::views::{program_name, real_connections, service_name};
use crate::{live, mark, Sel, Vigil};

pub const PROG_W: f32 = 230.0;
pub const PROG_H: f32 = 36.0;
pub const DEST_W: f32 = 250.0;
pub const DEST_H: f32 = 26.0;
const TOP: f32 = 44.0;

pub struct ProgNode {
    pub key: String,
    pub label: String,
    pub count: usize,
    pub x: f32,
    pub y: f32,
    pub hidden: bool,
}

pub struct DestNode {
    pub ip: String,
    pub service: String,
    pub scope: &'static str,
    pub x: f32,
    pub y: f32,
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
    pub prog_x: f32,
    pub dest_x: f32,
}

fn hidden_label(reason: &str) -> String {
    match reason {
        "other-user" => "Other users (hidden)".into(),
        "closed" => "Closing".into(),
        "protected" => "Protected (hidden)".into(),
        _ => "Unattributed".into(),
    }
}

/// Where everything goes in a `w` × `h` map (pixels, from the map's top-left corner).
pub fn geometry(d: &Snapshot, w: f32, h: f32) -> MapGeo {
    let mut per: BTreeMap<String, Vec<&Socket>> = BTreeMap::new();
    for s in real_connections(d) {
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
    let usable = (h - TOP - 16.0).max(60.0);
    let max_progs = ((usable / (PROG_H + 10.0)).floor() as usize).max(1);
    ranked.truncate(max_progs);
    let prog_x = (w * 0.30 - PROG_W / 2.0).max(150.0);
    let dest_x = (w - DEST_W - 28.0).max(prog_x + PROG_W + 120.0);
    let np = ranked.len().max(1);
    let prog_gap = usable / np as f32;
    let mut progs = vec![];
    for (i, (key, socks)) in ranked.iter().enumerate() {
        let hidden = key.starts_with("hidden:");
        progs.push(ProgNode {
            key: key.clone(),
            label: if hidden { hidden_label(&key[7..]) } else { program_name(d, key) },
            count: socks.len(),
            x: prog_x,
            y: TOP + prog_gap * (i as f32 + 0.5) - PROG_H / 2.0,
            hidden,
        });
    }
    // Destination slots, shared out by how many addresses each program has.
    let slots = ((usable / (DEST_H + 6.0)).floor() as usize).max(np);
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
    let total: usize = uniq.iter().map(Vec::len).sum::<usize>().max(1);
    let mut placed: Vec<(usize, String, Option<usize>)> = vec![];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (pi, ips) in uniq.iter().enumerate() {
        let fresh: Vec<&String> = ips.iter().filter(|ip| !seen.contains(*ip)).collect();
        let share = ((slots as f32 * ips.len() as f32 / total as f32).floor() as usize).max(1);
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
    let dest_gap = usable / placed.len().max(1) as f32;
    let mut dests = vec![];
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut more_of: HashMap<usize, usize> = HashMap::new();
    for (i, (pi, ip, more)) in placed.into_iter().enumerate() {
        let y = TOP + dest_gap * (i as f32 + 0.5) - DEST_H / 2.0;
        match more {
            Some(n) => {
                more_of.insert(pi, dests.len());
                dests.push(DestNode {
                    ip: String::new(),
                    service: String::new(),
                    scope: "",
                    x: dest_x,
                    y,
                    more: Some((pi, n)),
                });
            }
            None => {
                let sock = ranked[pi].1.iter().find(|s| s.remote_ip == ip);
                let service = sock.map_or(String::new(), |s| {
                    service_name(&s.proto, if s.direction == "in" { s.local_port } else { s.remote_port })
                });
                index.insert(ip.clone(), dests.len());
                dests.push(DestNode { scope: scope_of(&ip), ip, service, x: dest_x, y, more: None });
            }
        }
    }
    let mut edges = vec![];
    let mut done = BTreeSet::new();
    for (pi, (_, socks)) in ranked.iter().enumerate() {
        for s in socks {
            let di = index.get(&s.remote_ip).copied().or_else(|| more_of.get(&pi).copied());
            if let Some(di) = di {
                if done.insert((pi, di)) {
                    let all: Vec<&&Socket> = socks.iter().filter(|x| x.remote_ip == s.remote_ip).collect();
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
    MapGeo { pc: (64.0, TOP + usable / 2.0), progs, dests, edges, prog_x, dest_x }
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

impl Vigil {
    pub fn network_map(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = self.theme.clone();
        let Some(d) = &self.data else { return div().into_any_element() };
        let (w, h) =
            self.map_bounds.get().map_or((1100.0, 640.0), |b| (f32::from(b.size.width), f32::from(b.size.height)));
        let geo = geometry(d, w, h);
        let sel_prog = match &self.sel {
            Some(Sel::Program(k)) => geo.progs.iter().position(|p| &p.key == k),
            _ => None,
        };
        let sel_dest = match &self.sel {
            Some(Sel::Addr(ip)) => geo.dests.iter().position(|x| &x.ip == ip),
            _ => None,
        };
        let any_sel = sel_prog.is_some() || sel_dest.is_some();
        // Owned data for the painter.
        let lines: Vec<Stroke> = {
            let mut v = vec![];
            for (i, p) in geo.progs.iter().enumerate() {
                let on = sel_prog == Some(i);
                v.push((
                    curve((geo.pc.0 + 22.0, geo.pc.1), (p.x, p.y + PROG_H / 2.0)),
                    t.text[2].0 >> 8,
                    if any_sel && !on { 0.12 } else { 0.35 },
                    1.0,
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
                    0.1
                } else if on {
                    0.95
                } else {
                    0.5
                };
                v.push((
                    curve((p.x + PROG_W, p.y + PROG_H / 2.0), (q.x, q.y + DEST_H / 2.0)),
                    colour.0 >> 8,
                    alpha,
                    if on { 1.8 } else { 1.2 },
                ));
            }
            v
        };
        let dot = t.line[1].0 >> 8;
        let pc = geo.pc;
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
                // A quiet dot grid, so the space reads as a surface rather than a void.
                let (bw, bh) = (f32::from(b.size.width), f32::from(b.size.height));
                let mut y = 12.0;
                while y < bh {
                    let mut x = 12.0;
                    while x < bw {
                        w.paint_quad(gpui::fill(
                            gpui::Bounds::new(point(o.x + px(x), o.y + px(y)), gpui::size(px(1.2), px(1.2))),
                            mark::hsla(dot, 0.45),
                        ));
                        x += 24.0;
                    }
                    y += 24.0;
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
                mark::paint(w, o, &vigil_ui_core::motion::MarkFrame::at_rest(pc.0, pc.1, 22.0));
            },
        )
        .absolute()
        .top_0()
        .left_0()
        .size_full();

        let header = |x: f32, text: &str| {
            div()
                .absolute()
                .left(px(x))
                .top(px(14.0))
                .text_size(px(11.0))
                .text_color(c(t.text[2]))
                .child(text.to_string())
        };
        let mut nodes: Vec<AnyElement> = vec![
            header(24.0, "THIS PC").into_any_element(),
            header(geo.prog_x, "PROGRAMS").into_any_element(),
            header(geo.dest_x, "TALKING TO").into_any_element(),
            div()
                .absolute()
                .left(px(14.0))
                .top(px(pc.1 + 30.0))
                .w(px(100.0))
                .text_size(px(11.5))
                .text_color(c(t.text[1]))
                .truncate()
                .child(wording::printable(&self.device.name))
                .into_any_element(),
        ];
        for (i, p) in geo.progs.iter().enumerate() {
            let on = sel_prog == Some(i);
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
                    .w(px(PROG_W))
                    .h(px(PROG_H))
                    .px(px(8.0))
                    .flex()
                    .items_center()
                    .gap(px(9.0))
                    .rounded(px(PROG_H / 2.0))
                    .bg(if on { c(t.accent_soft) } else { c(t.bg[2]) })
                    .border_1()
                    .border_color(if on { c(t.accent) } else { c(t.line[1]) })
                    .when(any_sel && !on, |el| el.opacity(0.55))
                    .cursor_pointer()
                    .hover(|s| s.border_color(ca(Rgba(0xffffff40), 1.0)))
                    .child(if hidden {
                        div()
                            .size(px(22.0))
                            .rounded_full()
                            .bg(c(t.bg[4]))
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(gpui::svg().path("icons/eye.svg").size(px(13.0)).text_color(c(t.text[2])))
                            .into_any_element()
                    } else {
                        self.app_icon(&p.key, 22.0)
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .truncate()
                            .text_color(if hidden { c(t.text[2]) } else { c(t.text[0]) })
                            .child(p.label.clone()),
                    )
                    .child(
                        div()
                            .px(px(7.0))
                            .rounded(px(9.0))
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
                .w(px(DEST_W))
                .h(px(DEST_H))
                .px(px(10.0))
                .flex()
                .items_center()
                .gap(px(8.0))
                .rounded(px(6.0))
                .bg(if on { c(t.accent_soft) } else { c(t.bg[1]) })
                .border_1()
                .border_color(if on { c(t.accent) } else { c(t.line[0]) })
                .when(any_sel && !on, |el| el.opacity(0.5))
                .cursor_pointer()
                .text_size(px(12.0));
            let el = match q.more {
                Some((pi, n)) => {
                    let key = geo.progs[pi].key.clone();
                    base.child(div().text_color(c(t.text[2])).child(format!("+{n} more addresses"))).on_click(
                        cx.listener(move |this, _: &ClickEvent, _w, cx| {
                            this.set_tab(1, 1);
                            this.sel = Some(Sel::Program(key.clone()));
                            cx.notify();
                        }),
                    )
                }
                None => {
                    let ip = q.ip.clone();
                    let lan = matches!(q.scope, "lan" | "link-local");
                    base.child(div().size(px(7.0)).rounded_full().bg(if lan { c(t.accent) } else { c(t.live) }))
                        .child(div().flex_1().truncate().child(q.ip.clone()))
                        .child(div().text_size(px(11.0)).text_color(c(t.text[2])).child(q.service.clone()))
                        .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                            this.sel = if this.sel == Some(Sel::Addr(ip.clone())) {
                                None
                            } else {
                                Some(Sel::Addr(ip.clone()))
                            };
                            cx.notify();
                        }))
                }
            };
            nodes.push(el.into_any_element());
        }
        if let Some(c_) = self.callout(&geo, sel_prog, sel_dest, h, cx) {
            nodes.push(c_);
        }
        let legend = div()
            .absolute()
            .bottom(px(10.0))
            .left(px(16.0))
            .flex()
            .gap(px(16.0))
            .text_size(px(11.5))
            .text_color(c(t.text[2]))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(div().w(px(14.0)).h(px(2.0)).bg(c(t.live)))
                    .child("open, made by this PC"),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(div().w(px(14.0)).h(px(2.0)).bg(c(t.warn)))
                    .child("made to this PC"),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(div().w(px(14.0)).h(px(2.0)).bg(c(t.text[2])))
                    .child("closing"),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(div().size(px(7.0)).rounded_full().bg(c(t.accent)))
                    .child("local network"),
            );
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
            .into_any_element()
    }

    /// A small card beside the selected node, in the open space between the columns, so
    /// the map keeps its size and the node stays in view.
    fn callout(
        &self,
        geo: &MapGeo,
        sel_prog: Option<usize>,
        sel_dest: Option<usize>,
        h: f32,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let t = &self.theme;
        let d = self.data.as_ref()?;
        let w = 300.0;
        let line = |k: &str, v: String| {
            div()
                .flex()
                .gap(px(8.0))
                .child(div().w(px(92.0)).text_color(c(t.text[2])).child(k.to_string()))
                .child(div().flex_1().truncate().child(v))
        };
        let (left, top, body): (f32, f32, gpui::Div) = if let Some(i) = sel_prog {
            let p = &geo.progs[i];
            let socks: Vec<&Socket> =
                d.net.sockets.iter().filter(|s| s.program.as_deref() == Some(p.key.as_str())).collect();
            let pids: BTreeSet<u32> = socks.iter().flat_map(|s| s.pids.clone()).collect();
            let user =
                pids.iter().next().and_then(|pid| d.net.processes.get(pid)).map_or("-".to_string(), |p| p.user.clone());
            let first = d
                .events
                .iter()
                .filter(|e| {
                    e.kind == "first-seen" && e.detail.get("program").and_then(|v| v.as_str()) == Some(p.key.as_str())
                })
                .map(|e| e.ts)
                .fold(f64::NAN, f64::min);
            let pids_v: Vec<u32> = pids.iter().copied().collect();
            let name = p.label.clone();
            let icon = self.icons.as_ref().and_then(|i| i.for_exe(&p.key)).map(|x| x.to_string_lossy().into_owned());
            let body = div()
                .flex()
                .flex_col()
                .gap(px(6.0))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.0))
                        .child(self.app_icon(&p.key, 26.0))
                        .child(div().flex_1().text_size(px(15.0)).truncate().child(p.label.clone())),
                )
                .child(line("Path", wording::printable(&p.key)))
                .child(line("Processes", pids.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")))
                .child(line("User", user))
                .child(line(
                    "Online since",
                    if first.is_nan() {
                        "before history".into()
                    } else {
                        format!("{} ({})", self.clock(first), crate::ui::ago(first))
                    },
                ))
                .child(
                    div()
                        .pt(px(6.0))
                        .flex()
                        .gap(px(8.0))
                        .child(crate::ui::button(t, "co-point", "Point it out", false).on_click(cx.listener(
                            move |this, _: &ClickEvent, _w, cx| {
                                let _ = this.req.send(live::Req::Attention {
                                    pids: pids_v.clone(),
                                    name: name.clone(),
                                    icon: icon.clone(),
                                });
                                cx.notify();
                            },
                        )))
                        .child(crate::ui::button(t, "co-proc", "Show process", false).on_click(cx.listener(
                            |this, _: &ClickEvent, _w, cx| {
                                this.act(vigil_ui_core::keymap::Action::Pivot);
                                cx.notify();
                            },
                        ))),
                );
            (p.x + PROG_W + 18.0, p.y - 10.0, body)
        } else {
            let i = sel_dest?;
            let q = &geo.dests[i];
            let socks: Vec<&Socket> = d.net.sockets.iter().filter(|s| s.remote_ip == q.ip).collect();
            let progs: BTreeSet<String> = socks.iter().filter_map(|s| s.program.clone()).collect();
            let where_ = match q.scope {
                "internet" => "Internet",
                "lan" => "Local network",
                "link-local" => "This network link",
                other => other,
            };
            let body = div()
                .flex()
                .flex_col()
                .gap(px(6.0))
                .child(div().text_size(px(15.0)).child(q.ip.clone()))
                .child(line("Where", where_.to_string()))
                .child(line("Service", q.service.clone()))
                .child(line("Open", format!("{} connections", socks.len())))
                .child(line("Programs", progs.iter().map(|k| program_name(d, k)).collect::<Vec<_>>().join(", ")));
            (q.x - w - 18.0, q.y - 10.0, body)
        };
        let top = top.clamp(TOP, (h - 230.0).max(TOP));
        Some(
            div()
                .id("callout")
                .absolute()
                .left(px(left))
                .top(px(top))
                .w(px(w))
                .p(px(14.0))
                .rounded(px(t.radius))
                .bg(c(t.bg[2]))
                .border_1()
                .border_color(c(t.accent))
                .shadow_lg()
                .child(body)
                .with_animation(
                    id2(
                        "callout-in",
                        self.nav,
                        sel_prog.unwrap_or(1000) as u64 * 1000 + sel_dest.unwrap_or(999) as u64,
                    ),
                    gpui::Animation::new(std::time::Duration::from_millis(if self.reduced() { 1 } else { 200 }))
                        .with_easing(vigil_ui_core::motion::Spring::SNAPPY.easing(200.0)),
                    |el, d| el.opacity(d.clamp(0.0, 1.0)),
                )
                .into_any_element(),
        )
    }
}
