//! Home: this machine at a glance, filling the window with things worth knowing.
//!
//! Header: the device's name (hover: where it was read), its model and system, laptop or
//! desktop, the battery (laptops) or driver health (desktops), and the shield: how much
//! Vigil is watching, with a light that runs along its border every few seconds.
//! Then live numbers with their recent history, what is using the network, what is busiest,
//! where traffic goes by service, Vigil's activity and its coverage.

use gpui::{
    canvas, div, img, point, prelude::*, px, relative, AnyElement, ClickEvent, Context, Div, PathBuilder, Pixels,
    Point, Stateful,
};
use std::collections::BTreeMap;
use vigil_model::netaddr::scope_of;
use vigil_model::wording;
use vigil_sensor::device::{Health, Kind};
use vigil_ui_core::theme::Rgba;

use crate::ui::{c, ca, card, chip, id};
use crate::views::{program_name, real_connections, service_name};
use crate::{mark, Conn, Sel, Vigil};

/// The shield's light runs once along its border: after the arrival, when you point at
/// it, and when what Vigil can see changes. Never on a timer (a timer meant repainting the
/// whole window over and over).
pub const SHINE_MS: f32 = 1100.0;

/// One program's use: (CPU %, memory kB, processes, executable, name).
type Busy = (f32, u64, usize, String, String);

/// Shield status.
pub enum Watch {
    Full,
    Partial,
    Off,
}

/// Blue when Vigil sees everything, amber for a partial view, red when it sees nothing.
pub const SHIELD_BLUE: u32 = 0x5aa8ff;

fn shield_outline() -> Vec<(f32, f32)> {
    // A 28 x 32 heater shield: a gently arched top, straight sides, a curved point.
    let quad = |a: (f32, f32), c: (f32, f32), b: (f32, f32), t: f32| {
        let u = 1.0 - t;
        (u * u * a.0 + 2.0 * u * t * c.0 + t * t * b.0, u * u * a.1 + 2.0 * u * t * c.1 + t * t * b.1)
    };
    let mut pts = vec![];
    for i in 0..=8 {
        pts.push(quad((2.5, 4.5), (14.0, 0.5), (25.5, 4.5), i as f32 / 8.0));
    }
    pts.push((25.5, 15.0));
    for i in 1..=14 {
        pts.push(quad((25.5, 15.0), (25.0, 25.5), (14.0, 31.0), i as f32 / 14.0));
    }
    for i in 1..=14 {
        pts.push(quad((14.0, 31.0), (3.0, 25.5), (2.5, 15.0), i as f32 / 14.0));
    }
    pts.push((2.5, 4.5));
    pts
}

/// Keep the part of `poly` where `coord(p) <= v` (or `>= v`): one Sutherland-Hodgman step.
fn clip(poly: &[(f32, f32)], x_axis: bool, v: f32, below: bool) -> Vec<(f32, f32)> {
    let k = |p: (f32, f32)| if x_axis { p.0 } else { p.1 };
    let inside = |p: (f32, f32)| if below { k(p) <= v } else { k(p) >= v };
    let mut out = vec![];
    for i in 0..poly.len() {
        let (a, b) = (poly[i], poly[(i + 1) % poly.len()]);
        if inside(a) {
            out.push(a);
        }
        if inside(a) != inside(b) {
            let t = (v - k(a)) / (k(b) - k(a));
            out.push((a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t));
        }
    }
    out
}

/// The quartered shield at `scale`: four quarters split by a thin cross, two solid and two
/// soft (the 2 x 2 pattern), a crisp border, and the light running along the border only.
fn paint_shield(w: &mut gpui::Window, o: Point<Pixels>, scale: f32, colour: u32, shine: Option<f32>) {
    let at = |(x, y): (f32, f32)| point(o.x + px(x * scale), o.y + px(y * scale));
    let fill_poly = |w: &mut gpui::Window, poly: &[(f32, f32)], c: gpui::Hsla| {
        if poly.len() < 3 {
            return;
        }
        let mut b = PathBuilder::fill();
        b.move_to(at(poly[0]));
        for p in &poly[1..] {
            b.line_to(at(*p));
        }
        b.close();
        if let Ok(path) = b.build() {
            w.paint_path(path, c);
        }
    };
    let outline = shield_outline();
    let (cx_, cy_) = (14.0, 14.0);
    // The quarters sit inside the border with a small margin, split by a 1.6-unit cross.
    let inner: Vec<(f32, f32)> =
        outline.iter().map(|(x, y)| (cx_ + (x - cx_) * 0.8, cy_ + (y - cy_) * 0.8 + 0.4)).collect();
    let g = 0.8;
    fill_poly(w, &outline, mark::hsla(colour, 0.12));
    let quarters = [
        (clip(&clip(&inner, true, cx_ - g, true), false, cy_ - g, true), 0.95),
        (clip(&clip(&inner, true, cx_ + g, false), false, cy_ - g, true), 0.38),
        (clip(&clip(&inner, true, cx_ - g, true), false, cy_ + g, false), 0.38),
        (clip(&clip(&inner, true, cx_ + g, false), false, cy_ + g, false), 0.95),
    ];
    for (poly, alpha) in &quarters {
        fill_poly(w, poly, mark::hsla(colour, *alpha));
    }
    let mut border = PathBuilder::stroke(px(1.3 * scale));
    border.move_to(at(outline[0]));
    for p in &outline[1..] {
        border.line_to(at(*p));
    }
    if let Ok(path) = border.build() {
        w.paint_path(path, mark::hsla(colour, 1.0));
    }
    // The shine: a short bright stretch travelling once along the border.
    if let Some(head) = shine {
        let lens: Vec<f32> =
            outline.windows(2).map(|s| ((s[1].0 - s[0].0).powi(2) + (s[1].1 - s[0].1).powi(2)).sqrt()).collect();
        let total: f32 = lens.iter().sum();
        let point_at = |d: f32| {
            let mut d = d.rem_euclid(total);
            for (i, l) in lens.iter().enumerate() {
                if d <= *l {
                    let t = d / l;
                    let (a, b) = (outline[i], outline[i + 1]);
                    return (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t);
                }
                d -= l;
            }
            outline[0]
        };
        let tail = 0.25 * total;
        let steps = 14;
        for k in 0..steps {
            let d0 = head * total - tail * (k as f32 + 1.0) / steps as f32;
            let d1 = head * total - tail * k as f32 / steps as f32;
            let mut s = PathBuilder::stroke(px(1.6 * scale));
            s.move_to(at(point_at(d0)));
            s.line_to(at(point_at(d1)));
            if let Ok(path) = s.build() {
                let a =
                    (1.0 - k as f32 / steps as f32).powf(1.6) * (head * 3.0).min(1.0) * ((1.0 - head) * 3.0).min(1.0);
                w.paint_path(path, mark::hsla(0xffffff, 0.9 * a));
            }
        }
    }
}

impl Vigil {
    pub fn shining(&self) -> bool {
        self.shine_at.elapsed().as_secs_f32() * 1000.0 < SHINE_MS
    }

    pub fn watch(&self) -> (Watch, Vec<String>) {
        match (&self.conn, &self.data) {
            (Conn::Connected(bus), Some(d)) => {
                let full = d.procs.viewer.root;
                let mut why = vec![];
                why.push(if full {
                    "Watching every user's processes and connections.".to_string()
                } else {
                    "Watching only your own processes: the daemon runs as you (development mode).".to_string()
                });
                for s in &d.status.sources {
                    if s.live {
                        why.push(format!("Live: {} ({}).", s.signal, s.source));
                    }
                }
                let off: Vec<&str> = d.status.sources.iter().filter(|s| !s.live).map(|s| s.signal.as_str()).collect();
                if !off.is_empty() {
                    why.push(format!("Not built yet: {}.", off.join(", ")));
                }
                why.push(format!("Daemon on the {bus} bus."));
                (if full { Watch::Full } else { Watch::Partial }, why)
            }
            (Conn::Failed(e), _) => (Watch::Off, vec![e.clone(), "Nothing is being watched.".into()]),
            _ => (Watch::Off, vec!["Looking for the Vigil daemon.".into()]),
        }
    }

    /// Lines for the hover tip named `key` (first line is the title).
    pub fn tip_lines(&self, key: &str) -> Vec<String> {
        let dv = &self.device;
        match key {
            "device-name" => vec![
                dv.name.clone(),
                format!("Read from {}", dv.name_source),
                dv.model.clone().map_or("Model: not reported by the firmware".into(), |m| {
                    format!("Model: {m} (from {})", dv.model_source)
                }),
                format!("{} · kernel {}", dv.os, dv.kernel),
            ],
            "device-kind" => vec![
                match dv.kind {
                    Kind::Laptop => "Laptop".into(),
                    Kind::Desktop => "Desktop".into(),
                    Kind::Server => "Server".into(),
                    Kind::VirtualMachine => "Virtual machine".into(),
                    Kind::Unknown => "Computer".into(),
                },
                format!("Known from {}", dv.kind_source),
            ],
            "battery" => dv.battery.as_ref().map_or(vec![], |b| {
                vec![
                    format!("Battery {}%", b.percent),
                    format!("Status: {}", b.status),
                    format!("Read from {}", b.source),
                ]
            }),
            "drivers" => {
                let (h, why) = dv.driver_health(vigil_model::finding::now() as i64 / 86400);
                let title = match h {
                    Health::Good => "Drivers look current",
                    Health::Fair => "Drivers: worth an update",
                    Health::Poor => "Drivers look out of date",
                };
                [
                    vec![title.to_string()],
                    why,
                    vec!["From /proc/sys/kernel/version and /proc/sys/kernel/tainted.".into()],
                ]
                .concat()
            }
            "shield" => {
                let (w, why) = self.watch();
                let title = match w {
                    Watch::Full => "Watching this PC",
                    Watch::Partial => "Partial view",
                    Watch::Off => "Not watching",
                };
                [vec![title.to_string()], why].concat()
            }
            k if k.starts_with("cov:") => {
                let sig = &k[4..];
                self.data.as_ref().and_then(|d| d.status.sources.iter().find(|s| s.signal == sig)).map_or(vec![], |s| {
                    vec![
                        format!("{}: {}", s.signal, if s.live { s.source.as_str() } else { "not yet" }),
                        s.note.clone(),
                    ]
                })
            }
            _ => vec![],
        }
    }

    /// An element that shows the tip `key` while the mouse is over it.
    pub fn tip(&self, el: Stateful<Div>, key: &'static str, cx: &mut Context<Self>) -> Stateful<Div> {
        el.on_hover(cx.listener(move |this, hovered: &bool, _w, cx| {
            if *hovered {
                this.hover = Some(key);
            } else if this.hover == Some(key) {
                this.hover = None;
            }
            cx.notify();
        }))
    }

    /// A program's icon from the desktop, or a quiet placeholder of the same size.
    pub fn app_icon(&self, exe: &str, size: f32) -> AnyElement {
        let t = &self.theme;
        match self.icons.as_ref().and_then(|i| i.for_exe(exe)) {
            Some(path) => img(path).size(px(size)).flex_none().into_any_element(),
            None => div()
                .size(px(size))
                .flex_none()
                .rounded(px(size * 0.28))
                .bg(c(t.bg[4]))
                .flex()
                .items_center()
                .justify_center()
                .child(gpui::svg().path("icons/processes.svg").size(px(size * 0.62)).text_color(c(t.text[2])))
                .into_any_element(),
        }
    }

    fn header(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = self.theme.clone();
        let dv = &self.device;
        let kind_icon = match dv.kind {
            Kind::Laptop => "laptop",
            _ => "desktop",
        };
        let kind = self.tip(
            div()
                .id("device-kind")
                .size(px(44.0))
                .flex_none()
                .rounded(px(t.radius))
                .bg(c(t.bg[2]))
                .border_1()
                .border_color(c(t.line[0]))
                .flex()
                .items_center()
                .justify_center()
                .child(gpui::svg().path(format!("icons/{kind_icon}.svg")).size(px(22.0)).text_color(c(t.text[1]))),
            "device-kind",
            cx,
        );
        let name = self.tip(
            div().id("device-name").text_size(px(22.0)).text_color(c(t.text[0])).child(wording::printable(&dv.name)),
            "device-name",
            cx,
        );
        let pill = |idn: &'static str| {
            div()
                .id(idn)
                .h(px(28.0))
                .px(px(10.0))
                .flex()
                .items_center()
                .gap(px(7.0))
                .rounded(px(t.radius_sm))
                .bg(c(t.bg[2]))
                .border_1()
                .border_color(c(t.line[0]))
                .text_size(px(12.5))
        };
        let sub = [dv.model.clone(), Some(dv.os.clone())].into_iter().flatten().collect::<Vec<_>>().join(" · ");
        let power: AnyElement = match &dv.battery {
            Some(b) => {
                let col = if b.percent > 40 {
                    t.ok
                } else if b.percent > 20 {
                    t.warn
                } else {
                    t.danger
                };
                let charging = b.status == "Charging";
                self.tip(
                    pill("battery")
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .child(
                                    div()
                                        .w(px(22.0))
                                        .h(px(11.0))
                                        .p(px(1.5))
                                        .rounded(px(3.0))
                                        .border_1()
                                        .border_color(c(t.text[2]))
                                        .child(
                                            div()
                                                .h_full()
                                                .rounded(px(1.5))
                                                .bg(c(col))
                                                .w(relative(f32::from(b.percent) / 100.0)),
                                        ),
                                )
                                .child(div().w(px(2.0)).h(px(5.0)).rounded_r(px(1.0)).bg(c(t.text[2]))),
                        )
                        .child(div().text_color(c(t.text[0])).child(format!("{}%", b.percent)))
                        .when(charging, |el| el.child(div().text_color(c(t.text[2])).child("charging"))),
                    "battery",
                    cx,
                )
                .into_any_element()
            }
            None => {
                let (h, _) = dv.driver_health(vigil_model::finding::now() as i64 / 86400);
                let (icon, col, label) = match h {
                    Health::Good => ("thumb", t.ok, "Drivers current"),
                    Health::Fair => ("thumb-mid", t.warn, "Drivers: update"),
                    Health::Poor => ("thumb-down", t.danger, "Drivers outdated"),
                };
                self.tip(
                    pill("drivers")
                        .child(gpui::svg().path(format!("icons/{icon}.svg")).size(px(15.0)).text_color(c(col)))
                        .child(div().text_color(c(t.text[1])).child(label)),
                    "drivers",
                    cx,
                )
                .into_any_element()
            }
        };
        let (watch, _) = self.watch();
        let (colour, label) = match watch {
            Watch::Full => (SHIELD_BLUE, "Protected"),
            Watch::Partial => (t.warn.0 >> 8, "Partial view"),
            Watch::Off => (t.danger.0 >> 8, "Not watching"),
        };
        let shine = (!self.reduced() && self.shining())
            .then(|| vigil_ui_core::motion::ease_in_out(self.shine_at.elapsed().as_secs_f32() * 1000.0 / SHINE_MS));
        let shield = pill("shield")
            .child(
                canvas(|_, _, _| {}, move |b, _, w, _| paint_shield(w, b.origin, 0.62, colour, shine))
                    .w(px(18.0))
                    .h(px(20.0)),
            )
            .child(div().text_color(c(t.text[0])).child(label))
            .on_hover(cx.listener(|this, hovered: &bool, _w, cx| {
                if *hovered {
                    this.hover = Some("shield");
                    if !this.shining() {
                        this.shine_at = std::time::Instant::now();
                    }
                } else if this.hover == Some("shield") {
                    this.hover = None;
                }
                cx.notify();
            }));
        let facts = match &self.data {
            Some(d) => format!(
                "kernel {} · Vigil up {} · last look {}",
                dv.kernel,
                wording::span(d.status.uptime_s, true),
                self.last_update.map_or("-".into(), |u| {
                    let s = u.elapsed().as_secs();
                    if s < 3 {
                        "just now".to_string()
                    } else {
                        format!("{s} s ago")
                    }
                })
            ),
            None => format!("kernel {}", dv.kernel),
        };
        div()
            .flex()
            .items_center()
            .gap(px(14.0))
            .child(kind)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(3.0))
                    .child(div().flex().items_center().gap(px(10.0)).child(name).child(power).child(shield))
                    .child(div().text_size(px(12.5)).text_color(c(t.text[2])).child(sub)),
            )
            .child(div().flex_1())
            .child(div().text_size(px(12.0)).text_color(c(t.text[2])).child(facts))
            .into_any_element()
    }

    fn spark(&self, values: Vec<f32>, colour: Rgba) -> AnyElement {
        let col = colour.0 >> 8;
        canvas(
            |_, _, _| {},
            move |b, _, w, _| {
                if values.len() < 2 {
                    return;
                }
                let (bw, bh) = (f32::from(b.size.width), f32::from(b.size.height));
                // A flat series is a line across the middle, not a filled block.
                let max = values.iter().cloned().fold(f32::MIN, f32::max);
                let min = values.iter().cloned().fold(f32::MAX, f32::min);
                let pad = ((max - min) * 0.15).max(1.0);
                let (lo, hi) = (min - pad, max + pad);
                let at = |i: usize, v: f32| {
                    let x = bw * i as f32 / (values.len() - 1) as f32;
                    let y = bh - 2.0 - (bh - 4.0) * (v - lo) / (hi - lo);
                    point(b.origin.x + px(x), b.origin.y + px(y))
                };
                let mut area = PathBuilder::fill();
                area.move_to(point(b.origin.x, b.origin.y + px(bh)));
                for (i, v) in values.iter().enumerate() {
                    area.line_to(at(i, *v));
                }
                area.line_to(point(b.origin.x + px(bw), b.origin.y + px(bh)));
                area.close();
                if let Ok(p) = area.build() {
                    w.paint_path(p, mark::hsla(col, 0.08));
                }
                let mut line = PathBuilder::stroke(px(1.4));
                for (i, v) in values.iter().enumerate() {
                    if i == 0 {
                        line.move_to(at(i, *v));
                    } else {
                        line.line_to(at(i, *v));
                    }
                }
                if let Ok(p) = line.build() {
                    w.paint_path(p, mark::hsla(col, 0.9));
                }
            },
        )
        .w_full()
        .h(px(30.0))
        .into_any_element()
    }

    fn tile(&self, i: usize, label: &str, value: String, sub: String, spark: Option<(Vec<f32>, Rgba)>) -> AnyElement {
        let t = &self.theme;
        let (rise, op) = self.arrived.map_or((0.0, 1.0), |a| {
            vigil_ui_core::motion::card_rise(a.elapsed().as_secs_f32() * 1000.0, i, self.reduced())
        });
        card(t)
            .flex_1()
            .min_w(px(150.0))
            .px(px(16.0))
            .pt(px(14.0))
            .pb(px(10.0))
            .gap(px(2.0))
            .opacity(op)
            .relative()
            .top(px(rise))
            .child(div().text_size(px(12.0)).text_color(c(t.text[2])).child(label.to_string()))
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(8.0))
                    .child(div().text_size(px(26.0)).text_color(c(t.text[0])).child(value))
                    .child(div().pb(px(5.0)).text_size(px(11.5)).text_color(c(t.text[2])).child(sub)),
            )
            .child(match spark {
                Some((v, col)) => self.spark(v, col),
                None => div().h(px(30.0)).into_any_element(),
            })
            .into_any_element()
    }

    fn rise(&self, i: usize, el: Div) -> Div {
        let (rise, op) = self.arrived.map_or((0.0, 1.0), |a| {
            vigil_ui_core::motion::card_rise(a.elapsed().as_secs_f32() * 1000.0, i, self.reduced())
        });
        el.opacity(op).relative().top(px(rise))
    }

    fn section_title(&self, icon: &str, title: &str, note: String) -> Div {
        let t = &self.theme;
        div()
            .flex()
            .items_center()
            .gap(px(8.0))
            .pb(px(8.0))
            .child(gpui::svg().path(format!("icons/{icon}.svg")).size(px(15.0)).text_color(c(t.text[2])))
            .child(div().text_size(px(13.0)).text_color(c(t.text[1])).child(title.to_string()))
            .child(div().flex_1())
            .child(div().text_size(px(11.5)).text_color(c(t.text[2])).child(note))
    }

    pub fn home(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = self.theme.clone();
        let Some(d) = &self.data else { return div().into_any_element() };
        let n = |k: &str| self.counter(k).round() as i64;
        // Rows that fit the middle cards at this window height (no empty half-cards).
        let fit = ((self.viewport.get().1 - 590.0) / 40.0).floor().clamp(4.0, 24.0) as usize;
        let series = |i: usize| self.series.iter().map(|s| s[i]).collect::<Vec<f32>>();
        let day_ago = vigil_model::finding::now() - 86400.0;
        let new_today = d.events.iter().filter(|e| e.kind == "first-seen" && e.ts > day_ago).count();
        let daemon_cpu =
            d.procs.processes.iter().filter(|p| p.comm == "vigild").filter_map(|p| p.cpu_pct).sum::<f32>().max(0.0);
        let out_spark = if self.hist.len() > 1 { self.hist.clone() } else { series(2) };
        let tiles = div()
            .flex()
            .gap(px(12.0))
            .child(self.tile(0, "Processes", n("procs").to_string(), "running".into(), Some((series(0), t.accent))))
            .child(self.tile(
                1,
                "Outbound",
                n("out").to_string(),
                if self.hist.len() > 1 { "last hour".into() } else { "open now".into() },
                Some((out_spark, t.live)),
            ))
            .child(self.tile(
                2,
                "Online apps",
                n("programs").to_string(),
                "using the network".into(),
                Some((series(1), t.live_hi)),
            ))
            .child(self.tile(3, "Destinations", n("dests").to_string(), "addresses in history".into(), None))
            .child(self.tile(
                4,
                "Vigil",
                format!("{} MB", n("mem")),
                format!("{daemon_cpu:.1}% CPU · up {}", wording::span(d.status.uptime_s, true)),
                None,
            ));

        // Network activity: programs by open connections.
        let mut per: BTreeMap<String, usize> = BTreeMap::new();
        for s in real_connections(d) {
            if let Some(k) = &s.program {
                *per.entry(k.clone()).or_insert(0) += 1;
            }
        }
        let mut top: Vec<(String, usize)> = per.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let max = top.first().map_or(1, |x| x.1).max(1) as f32;
        let mut net_rows = vec![];
        for (i, (key, count)) in top.iter().take(fit).enumerate() {
            let key2 = key.clone();
            net_rows.push(
                div()
                    .id(id("talk", i as u64))
                    .h(px(40.0))
                    .px(px(8.0))
                    .flex()
                    .items_center()
                    .gap(px(10.0))
                    .rounded(px(t.radius_sm))
                    .cursor_pointer()
                    .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                    .child(self.app_icon(key, 22.0))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap(px(4.0))
                            .child(
                                div()
                                    .flex()
                                    .child(div().flex_1().truncate().child(program_name(d, key)))
                                    .child(div().text_color(c(t.text[2])).child(count.to_string())),
                            )
                            .child(
                                div().h(px(3.0)).w_full().rounded(px(2.0)).bg(c(t.bg[3])).child(
                                    div().h_full().rounded(px(2.0)).bg(c(t.live)).w(relative(*count as f32 / max)),
                                ),
                            ),
                    )
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.set_tab(1, 0);
                        this.sel = Some(Sel::Program(key2.clone()));
                        cx.notify();
                    })),
            );
        }
        let network = self
            .rise(5, card(&t).p(px(14.0)).flex_1().min_w(px(0.0)).overflow_hidden())
            .child(self.section_title("network", "Network activity", format!("{} programs", top.len())))
            .children(net_rows)
            .when(top.is_empty(), |el| {
                el.child(div().text_color(c(t.text[2])).child("Nothing is talking to another machine."))
            });

        // Busiest right now, per program (a browser's dozen processes are one line).
        let mut per_prog: BTreeMap<String, Busy> = BTreeMap::new();
        for p in d.procs.processes.iter().filter(|p| p.exe.is_some() || !p.cmdline.is_empty()) {
            let e = per_prog.entry(p.key.clone()).or_insert((
                0.0,
                0,
                0,
                p.exe.clone().unwrap_or_else(|| p.key.clone()),
                crate::views::display_name(Some(p), &p.key),
            ));
            e.0 += p.cpu_pct.unwrap_or(0.0);
            e.1 += p.rss_kb.unwrap_or(0);
            e.2 += 1;
        }
        let mut busy: Vec<(String, Busy)> = per_prog.into_iter().collect();
        busy.sort_by(|a, b| b.1 .0.partial_cmp(&a.1 .0).unwrap_or(std::cmp::Ordering::Equal).then(b.1 .1.cmp(&a.1 .1)));
        let cpu_max = busy.first().map_or(1.0, |x| x.1 .0).max(1.0);
        let mut busy_rows = vec![];
        for (i, (key, (cpu, kb, n, exe, name))) in busy.iter().take(fit).enumerate() {
            let pid = crate::views::main_pid(d, key);
            let cpu = *cpu;
            busy_rows.push(
                div()
                    .id(id("busy", i as u64))
                    .h(px(40.0))
                    .px(px(8.0))
                    .flex()
                    .items_center()
                    .gap(px(10.0))
                    .rounded(px(t.radius_sm))
                    .cursor_pointer()
                    .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                    .child(self.app_icon(exe, 22.0))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.0))
                            .flex()
                            .flex_col()
                            .gap(px(4.0))
                            .child(
                                div()
                                    .flex()
                                    .gap(px(8.0))
                                    .child(div().flex_1().min_w(px(0.0)).truncate().child(wording::printable(name)))
                                    .when(*n > 1, |el| {
                                        el.child(div().text_color(c(t.text[2])).child(format!("{n} processes")))
                                    })
                                    .child(
                                        div()
                                            .w(px(52.0))
                                            .flex()
                                            .justify_end()
                                            .text_color(c(t.text[1]))
                                            .child(format!("{cpu:.1}%")),
                                    )
                                    .child(
                                        div()
                                            .w(px(64.0))
                                            .flex()
                                            .justify_end()
                                            .text_color(c(t.text[2]))
                                            .child(crate::views::mem(*kb)),
                                    ),
                            )
                            .child(div().h(px(3.0)).w_full().rounded(px(2.0)).bg(c(t.bg[3])).child(
                                div().h_full().rounded(px(2.0)).bg(c(t.accent)).w(relative((cpu / cpu_max).min(1.0))),
                            )),
                    )
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.set_tab(2, 1);
                        this.sel = pid.map(Sel::Proc);
                        this.reveal.set(Some(gpui::ScrollStrategy::Center));
                        cx.notify();
                    })),
            );
        }
        let busiest = self
            .rise(6, card(&t).p(px(14.0)).flex_1().min_w(px(0.0)).overflow_hidden())
            .child(self.section_title("cpu", "Busiest right now", "per program · CPU · memory".into()))
            .children(busy_rows);

        // Traffic by service, and where it goes.
        let mut by_service: BTreeMap<String, usize> = BTreeMap::new();
        let (mut internet, mut lan) = (0usize, 0usize);
        for s in real_connections(d) {
            let port = if s.direction == "in" { s.local_port } else { s.remote_port };
            *by_service.entry(service_name(&s.proto, port)).or_insert(0) += 1;
            match scope_of(&s.remote_ip) {
                "lan" | "link-local" => lan += 1,
                _ => internet += 1,
            }
        }
        let mut services: Vec<(String, usize)> = by_service.into_iter().collect();
        services.sort_by_key(|x| std::cmp::Reverse(x.1));
        let total = (internet + lan).max(1) as f32;
        let svc_max = services.first().map_or(1, |x| x.1).max(1) as f32;
        let traffic =
            self.rise(7, card(&t).p(px(14.0)).flex_1().min_w(px(0.0)).overflow_hidden())
                .child(self.section_title("globe", "Traffic by service", format!("{} connections", internet + lan)))
                .child(
                    div()
                        .flex()
                        .h(px(8.0))
                        .rounded(px(4.0))
                        .overflow_hidden()
                        .bg(c(t.bg[3]))
                        .child(div().h_full().bg(c(t.live)).w(relative(internet as f32 / total)))
                        .child(div().h_full().bg(c(t.accent)).w(relative(lan as f32 / total))),
                )
                .child(
                    div()
                        .pt(px(6.0))
                        .pb(px(8.0))
                        .flex()
                        .gap(px(14.0))
                        .text_size(px(11.5))
                        .text_color(c(t.text[2]))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(6.0))
                                .child(div().size(px(8.0)).rounded_full().bg(c(t.live)))
                                .child(format!("Internet {internet}")),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(6.0))
                                .child(div().size(px(8.0)).rounded_full().bg(c(t.accent)))
                                .child(format!("Local network {lan}")),
                        ),
                )
                .children(services.iter().take(7).map(|(name, count)| {
                    div()
                        .py(px(5.0))
                        .flex()
                        .items_center()
                        .gap(px(10.0))
                        .child(div().w(px(110.0)).truncate().child(name.clone()))
                        .child(
                            div().flex_1().h(px(6.0)).rounded(px(3.0)).bg(c(t.bg[3])).child(
                                div().h_full().rounded(px(3.0)).bg(c(t.live)).w(relative(*count as f32 / svc_max)),
                            ),
                        )
                        .child(div().w(px(28.0)).text_color(c(t.text[2])).child(count.to_string()))
                }));

        // Activity and coverage.
        let activity = self
            .rise(8, card(&t).p(px(14.0)).flex_1().min_w(px(0.0)).overflow_hidden())
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(
                        self.section_title("activity", "Activity", format!("{new_today} new on the network today"))
                            .flex_1(),
                    )
                    .child(crate::ui::button(&t, "open-timeline", "Timeline", false).on_click(cx.listener(
                        |this, _: &ClickEvent, _w, cx| {
                            this.set_tab(8, 0);
                            cx.notify();
                        },
                    ))),
            )
            .children(
                {
                    // Repeated daemon starts are noise here; the timeline keeps them all.
                    let mut shown = vec![];
                    let mut daemon_seen = false;
                    for e in &d.events {
                        if e.kind == "daemon" {
                            if daemon_seen {
                                continue;
                            }
                            daemon_seen = true;
                        }
                        shown.push(e);
                        if shown.len() == 5 {
                            break;
                        }
                    }
                    shown
                }
                .into_iter()
                .map(|e| {
                    let colour = if e.kind == "first-seen" { t.live } else { t.text[2] };
                    div()
                        .py(px(6.0))
                        .flex()
                        .items_center()
                        .gap(px(10.0))
                        .border_t_1()
                        .border_color(c(t.line[0]))
                        .child(div().size(px(7.0)).rounded_full().bg(c(colour)))
                        .child(
                            div().flex_1().truncate().child(wording::printable(
                                &e.summary
                                    .replace("First time Vigil has seen ", "New on the network: ")
                                    .replace(" use the network", ""),
                            )),
                        )
                        .child(div().text_size(px(11.5)).text_color(c(t.text[2])).child(crate::ui::ago(e.ts)))
                }),
            );
        let mut cov = vec![];
        for s in &d.status.sources {
            let key: &'static str = match s.signal.as_str() {
                "processes" => "cov:processes",
                "connections" => "cov:connections",
                "dns" => "cov:dns",
                "file-opens" => "cov:file-opens",
                _ => "cov:autostart",
            };
            cov.push(
                self.tip(
                    div()
                        .id(key)
                        .py(px(6.0))
                        .flex()
                        .items_center()
                        .gap(px(10.0))
                        .border_t_1()
                        .border_color(c(t.line[0]))
                        .child(div().size(px(7.0)).rounded_full().bg(if s.live { c(t.ok) } else { c(t.text[2]) }))
                        .child(div().flex_1().child(match s.signal.as_str() {
                            "processes" => "Processes",
                            "connections" => "Connections",
                            "dns" => "DNS lookups",
                            "file-opens" => "Sensitive files",
                            _ => "Autostart",
                        }))
                        .child(if s.live { chip(s.source.clone(), t.ok) } else { chip("coming", t.text[2]) }),
                    key,
                    cx,
                ),
            );
        }
        let coverage = self
            .rise(9, card(&t).p(px(14.0)).w(px(360.0)).flex_none().overflow_hidden())
            .child(self.section_title("eye", "Coverage", "hover for details".into()))
            .children(cov);

        div()
            .size_full()
            .flex()
            .flex_col()
            .gap(px(14.0))
            .child(self.rise(0, div()).child(self.header(cx)))
            .child(tiles)
            .child(div().flex_1().min_h(px(240.0)).flex().gap(px(14.0)).child(network).child(busiest).child(traffic))
            .child(div().h(px(212.0)).flex_none().flex().gap(px(14.0)).child(activity).child(coverage))
            .into_any_element()
    }
}
