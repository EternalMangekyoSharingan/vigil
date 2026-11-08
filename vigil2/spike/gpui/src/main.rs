//! GPUI candidate for the toolkit spike (docs/RUST_REWRITE.md 5.1).
//!
//! Screens: `SPIKE_SCREEN=map` (2,000 nodes, ~2,400 animated edges, pan with drag, zoom
//! with the wheel) and `SPIKE_SCREEN=table` (palette + 100,000 rows, type to filter).
//! Tab switches screens. `SPIKE_SECONDS=N` runs a self-driving bench for N seconds and
//! prints one JSON line of measurements. All data is SYNTHETIC (common.rs).

#[path = "../../common.rs"]
mod common;

use common::{filter, graph, rows, Graph, Row, Stats, TYPING};
use gpui::{
    canvas, div, fill, point, prelude::*, px, rgb, rgba, size, uniform_list, App, Bounds, Context, FocusHandle, Hsla,
    KeyDownEvent, MouseButton, MouseDownEvent, MouseMoveEvent, PathBuilder, Pixels, Point, Render, ScrollDelta,
    ScrollEvent, ScrollStrategy, TextAlign, TextRun, UniformListScrollHandle, Window, WindowBounds, WindowOptions,
};
use std::{ops::Range, rc::Rc, time::Instant};

fn hsla(c: u32) -> Hsla {
    rgb(c).into()
}

struct Spike {
    screen: String,
    graph: Rc<Graph>,
    stats: Stats,
    t0: Instant,
    pan: (f32, f32),
    zoom: f32,
    drag: Option<Point<Pixels>>,
    rows: Rc<Vec<Row>>,
    filtered: Rc<Vec<usize>>,
    query: String,
    focus: FocusHandle,
    scroll: UniformListScrollHandle,
    bench: bool,
}

impl Spike {
    fn set_query(&mut self, q: String) {
        let t = Instant::now();
        self.filtered = Rc::new(filter(&self.rows, &q));
        self.stats.filter_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        self.query = q;
    }

    fn map(&self, t: f32) -> impl IntoElement {
        let g = self.graph.clone();
        let (ox, oy) = self.pan;
        let zoom = self.zoom;
        canvas(
            |_, _, _| {},
            move |bounds, _, window, cx| {
                let c = bounds.center();
                let to = |x: f32, y: f32| point(c.x + px(ox + x * zoom), c.y + px(oy + y * zoom));
                let mut b = PathBuilder::stroke(px(1.0));
                for e in &g.edges {
                    let (a, n) = (&g.nodes[e.a], &g.nodes[e.b]);
                    b.move_to(to(a.x, a.y));
                    b.line_to(to(n.x, n.y));
                }
                if let Ok(path) = b.build() {
                    window.paint_path(path, Hsla::from(rgba(0x5dbdb94d)));
                }
                for n in &g.nodes {
                    let s = if n.program { 9.0 } else { 5.0 };
                    let p = to(n.x, n.y);
                    let col = if n.program { hsla(0xff9f43) } else { hsla(0x62f3ff) };
                    window.paint_quad(
                        fill(Bounds::new(point(p.x - px(s / 2.0), p.y - px(s / 2.0)), size(px(s), px(s))), col)
                            .corner_radii(px(2.0)),
                    );
                }
                for e in &g.edges {
                    let f = (t * e.speed + e.phase).fract();
                    let (a, n) = (&g.nodes[e.a], &g.nodes[e.b]);
                    let p = to(a.x + (n.x - a.x) * f, a.y + (n.y - a.y) * f);
                    window.paint_quad(fill(
                        Bounds::new(point(p.x - px(1.5), p.y - px(1.5)), size(px(3.0), px(3.0))),
                        hsla(0x62f3ff),
                    ));
                }
                let font = window.text_style().font();
                for n in g.nodes.iter().filter(|n| n.program) {
                    let run = TextRun {
                        len: n.label.len(),
                        font: font.clone(),
                        color: hsla(0xe8e3ef),
                        background_color: None,
                        underline: None,
                        strikethrough: None,
                    };
                    let line = window.text_system().shape_line(n.label.clone().into(), px(11.0), &[run], None);
                    let p = to(n.x, n.y);
                    let _ = line.paint(point(p.x + px(7.0), p.y - px(7.0)), px(14.0), TextAlign::Left, None, window, cx);
                }
            },
        )
        .size_full()
    }

    fn table(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let count = self.filtered.len();
        div()
            .size_full()
            .flex()
            .flex_col()
            .child(
                div()
                    .h(px(40.0))
                    .px_3()
                    .flex()
                    .items_center()
                    .border_b_1()
                    .border_color(hsla(0x2d2637))
                    .child(format!("Ctrl K  {}|   {} of {} processes", self.query, count, self.rows.len())),
            )
            .child(
                uniform_list(
                    "procs",
                    count,
                    cx.processor(|this, range: Range<usize>, _w, _cx| {
                        range
                            .map(|i| {
                                let r = &this.rows[this.filtered[i]];
                                div()
                                    .h(px(28.0))
                                    .px_3()
                                    .flex()
                                    .gap_4()
                                    .items_center()
                                    .child(div().w(px(70.0)).child(r.pid.to_string()))
                                    .child(div().w(px(160.0)).text_color(hsla(0xff9f43)).child(r.name.clone()))
                                    .child(div().w(px(60.0)).child(r.user))
                                    .child(div().w(px(60.0)).child(format!("{:.1}", r.cpu)))
                                    .child(div().w(px(80.0)).child(format!("{:.0} MB", r.rss_mb)))
                                    .child(div().flex_1().truncate().text_color(hsla(0x9a90a8)).child(r.cmd.clone()))
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(&self.scroll)
                .flex_1(),
            )
    }
}

impl Render for Spike {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.stats.frame();
        if self.stats.done() {
            println!("{}", self.stats.report("gpui"));
            cx.quit();
        }
        let t = self.t0.elapsed().as_secs_f32();
        if self.bench {
            if self.screen == "map" {
                self.zoom = 0.8 + 0.4 * (t * 0.7).sin();
                self.pan = (200.0 * (t * 0.5).sin(), 120.0 * (t * 0.3).cos());
            } else {
                let step = (self.stats.frames / 3) as usize % TYPING.len();
                if TYPING[step] != self.query {
                    self.set_query(TYPING[step].to_string());
                }
                let n = self.filtered.len().max(1);
                self.scroll.scroll_to_item((self.stats.frames as usize * 7) % n, ScrollStrategy::Top);
            }
            window.request_animation_frame();
        } else if self.screen == "map" {
            window.request_animation_frame();
        }
        let body = if self.screen == "map" { self.map(t).into_any_element() } else { self.table(cx).into_any_element() };
        div()
            .size_full()
            .bg(hsla(0x110e15))
            .text_color(hsla(0xe8e3ef))
            .text_size(px(13.0))
            .track_focus(&self.focus)
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, _w, cx| {
                let k = &ev.keystroke;
                if k.key == "tab" {
                    this.screen = if this.screen == "map" { "table".into() } else { "map".into() };
                } else if this.screen == "table" {
                    if k.key == "backspace" {
                        let mut q = this.query.clone();
                        q.pop();
                        this.set_query(q);
                    } else if let Some(c) = &k.key_char {
                        if !k.modifiers.control {
                            let q = format!("{}{}", this.query, c);
                            this.set_query(q);
                        }
                    }
                }
                cx.notify();
            }))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, ev: &MouseDownEvent, _w, _cx| this.drag = Some(ev.position)),
            )
            .on_mouse_up(MouseButton::Left, cx.listener(|this, _, _w, _cx| this.drag = None))
            .on_mouse_move(cx.listener(|this, ev: &MouseMoveEvent, _w, cx| {
                if let Some(d) = this.drag {
                    this.pan.0 += f32::from(ev.position.x - d.x);
                    this.pan.1 += f32::from(ev.position.y - d.y);
                    this.drag = Some(ev.position);
                    cx.notify();
                }
            }))
            .on_scroll(cx.listener(|this, ev: &ScrollEvent, _w, cx| {
                if this.screen == "map" {
                    let dy = match ev.delta {
                        ScrollDelta::Pixels(p) => f32::from(p.y) / 100.0,
                        ScrollDelta::Lines(l) => l.y / 3.0,
                    };
                    this.zoom = (this.zoom * (1.0 + dy * 0.2)).clamp(0.1, 8.0);
                    cx.notify();
                }
            }))
            .child(body)
    }
}

fn main() {
    let start = Instant::now();
    common::spawn_idle_probe("gpui");
    gpui_platform::application().run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(1280.0), px(800.0)), cx);
        cx.open_window(
            WindowOptions { window_bounds: Some(WindowBounds::Windowed(bounds)), focus: true, ..Default::default() },
            move |window, cx| {
                cx.new(|cx| {
                    let focus = cx.focus_handle();
                    focus.focus(window, cx);
                    let rows = Rc::new(rows(100_000));
                    let filtered = Rc::new((0..rows.len()).collect());
                    Spike {
                        screen: common::screen(),
                        graph: Rc::new(graph()),
                        stats: Stats::new(start),
                        t0: Instant::now(),
                        pan: (0.0, 0.0),
                        zoom: 1.0,
                        drag: None,
                        rows,
                        filtered,
                        query: String::new(),
                        focus,
                        scroll: UniformListScrollHandle::new(),
                        bench: common::bench_seconds().is_some(),
                    }
                })
            },
        )
        .expect("open window");
        cx.activate(true);
    });
}
