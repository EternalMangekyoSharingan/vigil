//! iced candidate for the toolkit spike (docs/RUST_REWRITE.md 5.1).
//!
//! Same screens, data and bench as the GPUI candidate (see common.rs): `SPIKE_SCREEN`
//! picks map or table, Tab switches, `SPIKE_SECONDS=N` runs the self-driving bench and
//! prints one JSON line. All data is SYNTHETIC.

#[path = "../../common.rs"]
mod common;

use common::{filter, graph, rows, Graph, Row, Stats, TYPING};
use iced::widget::{canvas, column, container, operation, row, scrollable, text, text_input, Space};
use iced::{keyboard, mouse, Color, Element, Font, Length, Point, Rectangle, Renderer, Size, Subscription, Task, Theme};
use std::time::Instant;

const ROW_H: f32 = 28.0;

fn c(hex: u32) -> Color {
    Color::from_rgb8((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

struct Spike {
    screen: String,
    graph: Graph,
    stats: Stats,
    t0: Instant,
    t: f32,
    pan: (f32, f32),
    zoom: f32,
    rows: Vec<Row>,
    filtered: Vec<usize>,
    query: String,
    offset_y: f32,
    viewport_h: f32,
    bench: bool,
    reported: bool,
}

#[derive(Debug, Clone)]
enum Msg {
    Frame(Instant),
    Query(String),
    Scrolled(scrollable::Viewport),
    Pan(f32, f32),
    Zoom(f32),
    Toggle,
}

impl Spike {
    fn boot(start: Instant) -> (Self, Task<Msg>) {
        let rows = rows(100_000);
        let filtered = (0..rows.len()).collect();
        let s = Spike {
            screen: common::screen(),
            graph: graph(),
            stats: Stats::new(start),
            t0: Instant::now(),
            t: 0.0,
            pan: (0.0, 0.0),
            zoom: 1.0,
            rows,
            filtered,
            query: String::new(),
            offset_y: 0.0,
            viewport_h: 800.0,
            bench: common::bench_seconds().is_some(),
            reported: false,
        };
        (s, operation::focus("query"))
    }

    fn set_query(&mut self, q: String) {
        let t = Instant::now();
        self.filtered = filter(&self.rows, &q);
        self.stats.filter_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        self.query = q;
    }

    fn update(&mut self, m: Msg) -> Task<Msg> {
        match m {
            Msg::Frame(_) => {
                self.stats.frame();
                self.t = self.t0.elapsed().as_secs_f32();
                if self.stats.done() && !self.reported {
                    self.reported = true;
                    println!("{}", self.stats.report("iced"));
                    return iced::exit();
                }
                if self.bench {
                    if self.screen == "map" {
                        self.zoom = 0.8 + 0.4 * (self.t * 0.7).sin();
                        self.pan = (200.0 * (self.t * 0.5).sin(), 120.0 * (self.t * 0.3).cos());
                    } else {
                        let step = (self.stats.frames / 3) as usize % TYPING.len();
                        if TYPING[step] != self.query {
                            self.set_query(TYPING[step].to_string());
                        }
                        let n = self.filtered.len().max(1);
                        let y = ((self.stats.frames as usize * 7) % n) as f32 * ROW_H;
                        return operation::scroll_to("procs", scrollable::AbsoluteOffset { x: None, y: Some(y) });
                    }
                }
            }
            Msg::Query(q) => self.set_query(q),
            Msg::Scrolled(v) => {
                self.offset_y = v.absolute_offset().y;
                self.viewport_h = v.bounds().height;
            }
            Msg::Pan(dx, dy) => {
                self.pan.0 += dx;
                self.pan.1 += dy;
            }
            Msg::Zoom(dy) => self.zoom = (self.zoom * (1.0 + dy * 0.2)).clamp(0.1, 8.0),
            Msg::Toggle => self.screen = if self.screen == "map" { "table".into() } else { "map".into() },
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Msg> {
        let body: Element<'_, Msg> = if self.screen == "map" {
            canvas(MapView { g: &self.graph, t: self.t, pan: self.pan, zoom: self.zoom })
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        } else {
            self.table()
        };
        container(body)
            .style(|_| container::Style { background: Some(c(0x110e15).into()), text_color: Some(c(0xe8e3ef)), ..Default::default() })
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn table(&self) -> Element<'_, Msg> {
        let n = self.filtered.len();
        let first = ((self.offset_y / ROW_H) as usize).min(n);
        let end = (first + (self.viewport_h / ROW_H) as usize + 2).min(n);
        let visible = column((first..end).map(|i| {
            let r = &self.rows[self.filtered[i]];
            row![
                text(r.pid.to_string()).size(13).width(70),
                text(&r.name).size(13).width(160).color(c(0xff9f43)),
                text(r.user).size(13).width(60),
                text(format!("{:.1}", r.cpu)).size(13).width(60),
                text(format!("{:.0} MB", r.rss_mb)).size(13).width(80),
                text(&r.cmd).size(13).color(c(0x9a90a8)),
            ]
            .spacing(16)
            .height(ROW_H)
            .into()
        }));
        let content = column![
            Space::new().height(first as f32 * ROW_H),
            visible,
            Space::new().height((n - end) as f32 * ROW_H)
        ];
        column![
            row![
                text_input("Ctrl K  filter processes", &self.query).id("query").on_input(Msg::Query).size(13),
                text(format!("{} of {} processes", n, self.rows.len())).size(13),
            ]
            .spacing(12)
            .padding(8),
            scrollable(content).id("procs").on_scroll(Msg::Scrolled).height(Length::Fill),
        ]
        .into()
    }

    fn subscription(&self) -> Subscription<Msg> {
        let frames = if self.screen == "map" || self.bench { iced::window::frames().map(Msg::Frame) } else { Subscription::none() };
        let keys = keyboard::listen().filter_map(|e| match e {
            keyboard::Event::KeyPressed { key: keyboard::Key::Named(keyboard::key::Named::Tab), .. } => Some(Msg::Toggle),
            _ => None,
        });
        Subscription::batch([frames, keys])
    }
}

struct MapView<'a> {
    g: &'a Graph,
    t: f32,
    pan: (f32, f32),
    zoom: f32,
}

impl canvas::Program<Msg> for MapView<'_> {
    type State = Option<Point>;

    fn update(
        &self,
        drag: &mut Option<Point>,
        event: &iced::Event,
        _bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<Msg>> {
        match event {
            iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                *drag = cursor.position();
                None
            }
            iced::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                *drag = None;
                None
            }
            iced::Event::Mouse(mouse::Event::CursorMoved { position }) => {
                let d = (*drag)?;
                *drag = Some(*position);
                Some(canvas::Action::publish(Msg::Pan(position.x - d.x, position.y - d.y)))
            }
            iced::Event::Mouse(mouse::Event::WheelScrolled { delta }) => {
                let dy = match delta {
                    mouse::ScrollDelta::Lines { y, .. } => *y / 3.0,
                    mouse::ScrollDelta::Pixels { y, .. } => *y / 100.0,
                };
                Some(canvas::Action::publish(Msg::Zoom(dy)))
            }
            _ => None,
        }
    }

    fn draw(&self, _s: &Option<Point>, renderer: &Renderer, _theme: &Theme, bounds: Rectangle, _c: mouse::Cursor) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let (cx, cy) = (bounds.width / 2.0, bounds.height / 2.0);
        let to = |x: f32, y: f32| Point::new(cx + self.pan.0 + x * self.zoom, cy + self.pan.1 + y * self.zoom);
        let g = self.g;
        let edges = canvas::Path::new(|b| {
            for e in &g.edges {
                let (a, n) = (&g.nodes[e.a], &g.nodes[e.b]);
                b.move_to(to(a.x, a.y));
                b.line_to(to(n.x, n.y));
            }
        });
        frame.stroke(&edges, canvas::Stroke::default().with_color(Color { a: 0.3, ..c(0x5dbdb9) }).with_width(1.0));
        for n in &g.nodes {
            let s = if n.program { 9.0 } else { 5.0 };
            let p = to(n.x, n.y);
            frame.fill_rectangle(Point::new(p.x - s / 2.0, p.y - s / 2.0), Size::new(s, s), if n.program { c(0xff9f43) } else { c(0x62f3ff) });
        }
        for e in &g.edges {
            let f = (self.t * e.speed + e.phase).fract();
            let (a, n) = (&g.nodes[e.a], &g.nodes[e.b]);
            let p = to(a.x + (n.x - a.x) * f, a.y + (n.y - a.y) * f);
            frame.fill_rectangle(Point::new(p.x - 1.5, p.y - 1.5), Size::new(3.0, 3.0), c(0x62f3ff));
        }
        for n in g.nodes.iter().filter(|n| n.program) {
            let p = to(n.x, n.y);
            frame.fill_text(canvas::Text {
                content: n.label.clone(),
                position: Point::new(p.x + 7.0, p.y - 7.0),
                color: c(0xe8e3ef),
                size: 11.0.into(),
                font: Font::DEFAULT,
                ..Default::default()
            });
        }
        vec![frame.into_geometry()]
    }
}

fn main() -> iced::Result {
    let start = Instant::now();
    common::spawn_idle_probe("iced");
    iced::application(move || Spike::boot(start), Spike::update, Spike::view)
        .subscription(Spike::subscription)
        .title("Vigil spike: iced")
        .window_size(Size::new(1280.0, 800.0))
        .run()
}
