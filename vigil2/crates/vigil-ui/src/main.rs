//! The Vigil app.
//!
//! Milestone 1 (docs/RUST_REWRITE.md section 8): the shell. A left rail with every area,
//! a top bar, the command palette (Ctrl K), Settings (,), the shortcut sheet (?), the
//! arrival animation on the Vigil mark (or g h), and the full keyboard map. The areas
//! say what they will show and which milestone brings it; they never show made-up data.
//!
//! Everything that does not need a toolkit (keymap, palette ranking, motion curves,
//! theme, settings) lives in `vigil-ui-core` and is tested there.
//!
//! `vigil --measure-startup` prints the time from process start to the first frame and
//! exits (the milestone asks for under 300 ms).

mod icons;

use gpui::{
    canvas, div, fill, point, prelude::*, px, quad, rgba, size, svg, App, BorderStyle, Bounds, ClickEvent, Context,
    ElementId, FocusHandle, Hsla, KeyDownEvent, PathBuilder, Pixels, Point, Render, SharedString, TextAlign, TextRun,
    Window, WindowBounds, WindowOptions,
};
use std::time::{Duration, Instant};
use vigil_ui_core::areas::{info, AREAS};
use vigil_ui_core::keymap::{show_chord, Action, Key, Keymap, Outcome};
use vigil_ui_core::motion::{self, MotionPref, Spring};
use vigil_ui_core::palette::{self, Entry, Kind};
use vigil_ui_core::settings::{config_dir, Density, UiSettings, View};
use vigil_ui_core::theme::{self, Rgba, Theme};

fn c(x: Rgba) -> Hsla {
    rgba(x.0).into()
}

fn ca(x: Rgba, alpha: f32) -> Hsla {
    let mut h = c(x);
    h.a *= alpha.clamp(0.0, 1.0);
    h
}

#[derive(Clone, Copy, PartialEq)]
enum Overlay {
    None,
    Palette,
    Settings,
    Shortcuts,
}

struct Vigil {
    theme: Theme,
    theme_problems: Vec<String>,
    settings: UiSettings,
    settings_problem: Option<String>,
    keymap: Keymap,
    keymap_problem: Option<String>,
    area: usize,
    tab: Vec<usize>,
    history: Vec<usize>,
    future: Vec<usize>,
    overlay: Overlay,
    query: String,
    pick: usize,
    entries: Vec<Entry>,
    /// Rail marker: from index, to index, when it started moving.
    marker: (f32, f32, Instant),
    /// When the arrival started, if it is playing.
    arrival: Option<Instant>,
    /// When the last arrival ended (Home's cards rise after it).
    arrived: Option<Instant>,
    toast: Option<(String, Instant)>,
    focus: FocusHandle,
    started: Instant,
    first_frame: Option<Duration>,
    measure_startup: bool,
    desktop_reduced: bool,
    user: String,
}

/// GNOME and GTK keep "enable animations" in settings.ini; KDE in kdeglobals.
fn desktop_reduced_motion() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let read = |p: &str| std::fs::read_to_string(format!("{home}/{p}")).unwrap_or_default().to_lowercase();
    read(".config/gtk-3.0/settings.ini").contains("gtk-enable-animations=false")
        || read(".config/gtk-4.0/settings.ini").contains("gtk-enable-animations=false")
        || read(".config/kdeglobals").contains("animationdurationfactor=0\n")
}

fn key_from(ev: &KeyDownEvent) -> Key {
    let k = &ev.keystroke;
    let printable = k.key_char.as_deref().filter(|s| s.chars().count() == 1 && !s.chars().all(char::is_whitespace));
    match printable {
        Some(ch) if !k.modifiers.control && !k.modifiers.alt => Key::plain(ch),
        _ => Key { ctrl: k.modifiers.control, alt: k.modifiers.alt, shift: false, key: k.key.to_lowercase() },
    }
}

impl Vigil {
    fn new(focus: FocusHandle, started: Instant) -> Self {
        let dir = config_dir();
        let (settings, settings_problem) =
            dir.as_ref().map(|d| UiSettings::load(&d.join("ui.toml"))).unwrap_or_default();
        let (keymap, keymap_problem) =
            match dir.as_ref().and_then(|d| std::fs::read_to_string(d.join("keys.toml")).ok()) {
                Some(text) => match Keymap::with_overrides(&text) {
                    Ok(k) => (k, None),
                    Err(e) => (Keymap::default(), Some(format!("keys.toml ignored: {e}"))),
                },
                None => (Keymap::default(), None),
            };
        let mut v = Vigil {
            theme: theme::by_name(&settings.theme),
            theme_problems: vec![],
            settings,
            settings_problem,
            keymap,
            keymap_problem,
            area: 0,
            tab: vec![0; AREAS.len()],
            history: vec![],
            future: vec![],
            overlay: Overlay::None,
            query: String::new(),
            pick: 0,
            entries: vec![],
            marker: (0.0, 0.0, Instant::now()),
            arrival: None,
            arrived: None,
            toast: None,
            focus,
            started,
            first_frame: None,
            measure_startup: std::env::args().any(|a| a == "--measure-startup"),
            desktop_reduced: desktop_reduced_motion(),
            user: std::env::var("USER").unwrap_or_default(),
        };
        v.reload_theme();
        v.entries = v.palette_entries();
        v
    }

    fn reduced(&self) -> bool {
        motion::reduced(self.settings.motion, self.desktop_reduced)
    }

    fn reload_theme(&mut self) {
        let base = theme::by_name(&self.settings.theme);
        let file = config_dir().and_then(|d| std::fs::read_to_string(d.join("theme.toml")).ok());
        (self.theme, self.theme_problems) = match file {
            Some(text) => theme::with_overrides(base, &text),
            None => (base, vec![]),
        };
    }

    fn save_settings(&mut self) {
        if let Some(d) = config_dir() {
            if let Err(e) = self.settings.save(&d.join("ui.toml")) {
                self.say(format!("Could not save settings: {e}"));
            }
        }
    }

    fn say(&mut self, text: impl Into<String>) {
        self.toast = Some((text.into(), Instant::now()));
    }

    fn keys_hint(&self, a: Action) -> String {
        self.keymap.keys_for(a).first().map(|c| show_chord(c)).unwrap_or_default()
    }

    fn palette_entries(&self) -> Vec<Entry> {
        let mut out = vec![];
        for (i, a) in AREAS.iter().enumerate() {
            out.push(Entry {
                title: a.name.into(),
                hint: format!("{} · {}", self.keys_hint(Action::GoArea(i)), a.question),
                kind: Kind::Area,
                id: format!("area:{i}"),
            });
            for (t, tab) in a.tabs.iter().enumerate() {
                out.push(Entry {
                    title: format!("{}: {tab}", a.name),
                    hint: "tab".into(),
                    kind: Kind::Tab,
                    id: format!("tab:{i}:{t}"),
                });
            }
        }
        for a in [Action::Settings, Action::Shortcuts, Action::Arrival, Action::ToggleExpert] {
            out.push(Entry {
                title: a.describe(),
                hint: self.keys_hint(a),
                kind: Kind::Action,
                id: format!("action:{}", a.name()),
            });
        }
        for (name, id) in [
            ("Theme: Dark", "theme:dark"),
            ("Theme: Light", "theme:light"),
            ("Theme: High contrast", "theme:high-contrast"),
        ] {
            out.push(Entry { title: name.into(), hint: "setting".into(), kind: Kind::Setting, id: id.into() });
        }
        for (name, id) in [
            ("Motion: System", "motion:system"),
            ("Motion: Full", "motion:full"),
            ("Motion: Reduced", "motion:reduced"),
        ] {
            out.push(Entry { title: name.into(), hint: "setting".into(), kind: Kind::Setting, id: id.into() });
        }
        for (name, id) in [("Density: Comfortable", "density:comfortable"), ("Density: Compact", "density:compact")] {
            out.push(Entry { title: name.into(), hint: "setting".into(), kind: Kind::Setting, id: id.into() });
        }
        out
    }

    fn go(&mut self, area: usize) {
        if area == self.area {
            return;
        }
        self.history.push(self.area);
        self.future.clear();
        self.move_marker(area);
    }

    fn move_marker(&mut self, area: usize) {
        let now = self.marker_pos();
        self.marker = (now, area as f32, Instant::now());
        self.area = area;
    }

    fn marker_pos(&self) -> f32 {
        let (from, to, t0) = self.marker;
        if self.reduced() {
            return to;
        }
        from + (to - from) * Spring::SNAPPY.value(t0.elapsed().as_secs_f32())
    }

    fn choose(&mut self, id: &str) {
        let parts: Vec<&str> = id.split(':').collect();
        match parts.as_slice() {
            ["area", i] => self.go(i.parse().unwrap_or(0)),
            ["tab", i, t] => {
                let i: usize = i.parse().unwrap_or(0);
                self.go(i);
                self.tab[i] = t.parse().unwrap_or(0);
            }
            ["action", name] => {
                if let Some(a) = Action::parse(name) {
                    self.overlay = Overlay::None;
                    self.act(a);
                    return;
                }
            }
            ["theme", name] => {
                self.settings.theme = (*name).into();
                self.reload_theme();
                self.save_settings();
            }
            ["motion", m] => {
                self.settings.motion = match *m {
                    "full" => MotionPref::Full,
                    "reduced" => MotionPref::Reduced,
                    _ => MotionPref::System,
                };
                self.save_settings();
            }
            ["density", d] => {
                self.settings.density = if *d == "compact" { Density::Compact } else { Density::Comfortable };
                self.save_settings();
            }
            _ => {}
        }
        self.overlay = Overlay::None;
    }

    fn act(&mut self, a: Action) {
        match a {
            Action::Palette => {
                self.overlay = Overlay::Palette;
                self.query.clear();
                self.pick = 0;
            }
            Action::GoArea(i) => self.go(i),
            Action::Arrival => {
                self.go(0);
                self.arrival = if self.reduced() { None } else { Some(Instant::now()) };
                if self.reduced() {
                    self.arrived = Some(Instant::now());
                }
            }
            Action::Back => {
                if self.overlay != Overlay::None {
                    self.overlay = Overlay::None;
                } else if let Some(prev) = self.history.pop() {
                    self.future.push(self.area);
                    self.move_marker(prev);
                }
            }
            Action::HistoryBack => {
                if let Some(prev) = self.history.pop() {
                    self.future.push(self.area);
                    self.move_marker(prev);
                }
            }
            Action::HistoryForward => {
                if let Some(next) = self.future.pop() {
                    self.history.push(self.area);
                    self.move_marker(next);
                }
            }
            Action::PrevTab | Action::NextTab => {
                let n = info(AREAS[self.area].area).tabs.len();
                let t = &mut self.tab[self.area];
                *t = if a == Action::NextTab { (*t + 1) % n } else { (*t + n - 1) % n };
            }
            Action::Settings => {
                self.overlay = if self.overlay == Overlay::Settings { Overlay::None } else { Overlay::Settings }
            }
            Action::Shortcuts => {
                self.overlay = if self.overlay == Overlay::Shortcuts { Overlay::None } else { Overlay::Shortcuts }
            }
            Action::ToggleExpert => {
                let v = self.settings.toggle_view(AREAS[self.area].id);
                self.save_settings();
                self.say(format!("{}: {}", AREAS[self.area].name, if v == View::Expert { "Expert" } else { "Guided" }));
            }
            Action::Down | Action::Up if self.overlay == Overlay::Palette => {
                let n = palette::search(&self.entries, &self.query, 12).len().max(1);
                self.pick = if a == Action::Down { (self.pick + 1) % n } else { (self.pick + n - 1) % n };
            }
            Action::Open if self.overlay == Overlay::Palette => {
                let hits = palette::search(&self.entries, &self.query, 12);
                if let Some(h) = hits.get(self.pick) {
                    let id = self.entries[h.index].id.clone();
                    self.choose(&id);
                }
            }
            // Actions on a selection: this milestone has no lists yet, and says so.
            other => self.say(format!("{}: nothing is selected yet (lists arrive with milestone 3)", other.describe())),
        }
    }

    fn on_key(&mut self, ev: &KeyDownEvent, cx: &mut Context<Self>) {
        let typing = self.overlay == Overlay::Palette;
        if let Some(t0) = self.arrival {
            // Any key skips the arrival.
            if t0.elapsed().as_secs_f32() * 1000.0 < motion::ARRIVAL_MS {
                self.arrival = None;
                self.arrived = Some(Instant::now());
                cx.notify();
                return;
            }
        }
        let key = key_from(ev);
        if typing && !key.ctrl && !key.alt {
            match key.key.as_str() {
                "down" | "up" | "enter" | "escape" => {}
                "backspace" => {
                    self.query.pop();
                    self.pick = 0;
                    cx.notify();
                    return;
                }
                k if k.chars().count() == 1 => {
                    self.query.push_str(k);
                    self.pick = 0;
                    cx.notify();
                    return;
                }
                "space" => {
                    self.query.push(' ');
                    cx.notify();
                    return;
                }
                _ => {}
            }
        }
        let typing_now = typing && !matches!(key.key.as_str(), "down" | "up" | "enter");
        match self.keymap.feed(key, typing_now) {
            Outcome::Action(a) => self.act(a),
            Outcome::Pending(_) | Outcome::Unbound => {}
        }
        cx.notify();
    }

    // ---- drawing ------------------------------------------------------------------------

    fn rail(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = &self.theme;
        let item_h = 56.0;
        let top = 64.0;
        let marker_y = top + self.marker_pos() * item_h;
        let mut items = vec![];
        for (i, a) in AREAS.iter().enumerate() {
            let here = i == self.area;
            let col = if here { t.text[0] } else { t.text[2] };
            items.push(
                div()
                    .id(ElementId::NamedInteger("rail".into(), i as u64))
                    .h(px(item_h))
                    .w_full()
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .gap_1()
                    .cursor_pointer()
                    .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                    .child(svg().path(format!("icons/{}.svg", a.id)).size(px(20.0)).text_color(if here {
                        c(t.accent)
                    } else {
                        c(col)
                    }))
                    .child(div().text_size(px(10.0)).text_color(c(col)).child(a.name))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.go(i);
                        cx.notify();
                    })),
            );
        }
        let initial: String =
            self.user.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_else(|| "?".into());
        div()
            .w(px(t.rail_width))
            .h_full()
            .flex_none()
            .bg(c(t.bg[1]))
            .border_r_1()
            .border_color(c(t.line[0]))
            .relative()
            .flex()
            .flex_col()
            .child(
                div()
                    .id("mark")
                    .h(px(top))
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .child(
                        canvas(
                            |_, _, _| {},
                            |b, _, w, _| {
                                paint_mark(
                                    w,
                                    b.center(),
                                    0.9,
                                    &[motion::Face { opacity: 1.0, dx: 0.0, dy: 0.0, scale: 1.0 }; 3],
                                    1.0,
                                )
                            },
                        )
                        .size(px(36.0)),
                    )
                    .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                        this.act(Action::Arrival);
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .absolute()
                    .left_0()
                    .top(px(marker_y + 14.0))
                    .w(px(3.0))
                    .h(px(item_h - 28.0))
                    .rounded_r(px(2.0))
                    .bg(c(t.accent)),
            )
            .children(items)
            .child(div().flex_1())
            .child(
                div()
                    .id("gear")
                    .h(px(48.0))
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .child(svg().path("icons/gear.svg").size(px(20.0)).text_color(c(t.text[1])))
                    .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                        this.act(Action::Settings);
                        cx.notify();
                    })),
            )
            .child(
                div().h(px(56.0)).flex().items_center().justify_center().child(
                    div()
                        .size(px(28.0))
                        .rounded_full()
                        .bg(c(t.bg[4]))
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_size(px(12.0))
                        .text_color(c(t.text[0]))
                        .child(initial),
                ),
            )
    }

    fn top_bar(&self) -> impl IntoElement {
        let t = &self.theme;
        let a = &AREAS[self.area];
        let tabs = a.tabs.iter().enumerate().map(|(i, name)| {
            let on = i == self.tab[self.area];
            div()
                .px_3()
                .h_full()
                .flex()
                .items_center()
                .border_b_2()
                .border_color(if on { c(t.accent) } else { ca(t.accent, 0.0) })
                .text_color(if on { c(t.text[0]) } else { c(t.text[2]) })
                .child(*name)
        });
        let view = if self.settings.view(a.id) == View::Expert { "Expert" } else { "Guided" };
        div()
            .h(px(52.0))
            .flex_none()
            .flex()
            .items_center()
            .gap_4()
            .px(px(t.pad))
            .border_b_1()
            .border_color(c(t.line[0]))
            .child(div().text_size(px(17.0)).text_color(c(t.text[0])).child(a.name))
            .child(div().h_full().flex().children(tabs))
            .child(div().flex_1())
            .child(div().text_size(px(12.0)).text_color(c(t.text[2])).child(format!("{view} · x")))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(12.0))
                    .text_color(c(t.text[2]))
                    .child(div().size(px(7.0)).rounded_full().bg(c(t.text[2])))
                    .child("Daemon not connected (milestone 2)"),
            )
            .child(
                div()
                    .h(px(t.control_height))
                    .px_3()
                    .flex()
                    .items_center()
                    .gap_2()
                    .rounded(px(t.radius_sm))
                    .border_1()
                    .border_color(c(t.line[1]))
                    .text_color(c(t.text[1]))
                    .child(svg().path("icons/search.svg").size(px(16.0)).text_color(c(t.text[1])))
                    .child("Jump to…")
                    .child(div().text_size(px(11.0)).text_color(c(t.text[2])).child(self.keys_hint(Action::Palette))),
            )
    }

    fn content(&self) -> impl IntoElement {
        let t = &self.theme;
        let a = &AREAS[self.area];
        let milestone = match a.id {
            "home" | "cases" => "milestone 5",
            "network" | "processes" => "milestone 3",
            "autostart" | "files" | "software" => "milestone 4",
            _ => "milestone 6",
        };
        let after = self.arrived.map(|t0| t0.elapsed().as_secs_f32() * 1000.0).unwrap_or(f32::MAX);
        let card = |i: usize, title: String, body: String| {
            let (dy, op) = if self.area == 0 { motion::card_rise(after, i, self.reduced()) } else { (0.0, 1.0) };
            div()
                .mt(px(dy))
                .opacity(op)
                .p(px(t.pad))
                .rounded(px(t.radius))
                .bg(c(t.bg[2]))
                .border_1()
                .border_color(c(t.line[0]))
                .flex()
                .flex_col()
                .gap_2()
                .child(div().text_size(px(15.0)).text_color(c(t.text[0])).child(title))
                .child(div().text_color(c(t.text[1])).child(body))
        };
        let was = a.was.map(|w| format!(" It grows from Vigil 1's {w}.")).unwrap_or_default();
        div()
            .flex_1()
            .p(px(t.pad))
            .flex()
            .flex_col()
            .gap(px(if self.settings.density == Density::Compact { 10.0 } else { 16.0 }))
            .child(card(0, a.question.to_string(), format!("{} arrives in {milestone}.{was} Until then this page shows nothing rather than made-up data.", a.name)))
            .child(card(
                1,
                "Keyboard".into(),
                format!(
                    "{} palette · 1–9 or g + letter to move · [ ] tabs · , Settings · ? all shortcuts · x Guided / Expert.",
                    self.keys_hint(Action::Palette)
                ),
            ))
    }

    fn palette(&self) -> impl IntoElement {
        let t = &self.theme;
        let hits = palette::search(&self.entries, &self.query, 12);
        let rows = hits.iter().enumerate().map(|(n, h)| {
            let e = &self.entries[h.index];
            let on = n == self.pick;
            let mut runs = vec![];
            for (ci, ch) in e.title.chars().enumerate() {
                let hit = h.matched.contains(&ci);
                runs.push(div().text_color(if hit { c(t.accent) } else { c(t.text[0]) }).child(ch.to_string()));
            }
            div()
                .h(px(36.0))
                .px_3()
                .flex()
                .items_center()
                .gap_3()
                .rounded(px(t.radius_sm))
                .bg(if on { c(t.accent_soft) } else { ca(t.bg[2], 0.0) })
                .child(div().w(px(56.0)).text_size(px(11.0)).text_color(c(t.text[2])).child(e.kind.label()))
                .child(div().flex().children(runs))
                .child(div().flex_1())
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(c(t.text[2]))
                        .truncate()
                        .max_w(px(300.0))
                        .child(e.hint.clone()),
                )
        });
        let empty = hits.is_empty();
        modal(t, 640.0)
            .child(
                div()
                    .h(px(48.0))
                    .px_4()
                    .flex()
                    .items_center()
                    .gap_3()
                    .border_b_1()
                    .border_color(c(t.line[0]))
                    .child(svg().path("icons/search.svg").size(px(18.0)).text_color(c(t.text[1])))
                    .child(if self.query.is_empty() {
                        div().text_color(c(t.text[2])).child("Areas, tabs, actions, settings…")
                    } else {
                        div().text_color(c(t.text[0])).child(format!("{}▏", self.query))
                    }),
            )
            .child(div().p_2().flex().flex_col().children(rows).when(empty, |d| {
                d.child(
                    div()
                        .p_3()
                        .text_color(c(t.text[2]))
                        .child("Nothing matches. Findings, processes and addresses join the palette with milestone 3."),
                )
            }))
    }

    fn settings_sheet(&self) -> impl IntoElement {
        let t = &self.theme;
        let row = |title: &str, value: String, hint: &str| {
            div()
                .py_3()
                .flex()
                .flex_col()
                .gap_1()
                .border_b_1()
                .border_color(c(t.line[0]))
                .child(
                    div()
                        .flex()
                        .child(div().text_color(c(t.text[0])).child(title.to_string()))
                        .child(div().flex_1())
                        .child(div().text_color(c(t.accent)).child(value)),
                )
                .child(div().text_size(px(12.0)).text_color(c(t.text[2])).child(hint.to_string()))
        };
        let motion = match self.settings.motion {
            MotionPref::System => format!("System ({})", if self.desktop_reduced { "reduced" } else { "full" }),
            MotionPref::Full => "Full".into(),
            MotionPref::Reduced => "Reduced".into(),
        };
        let mut notes: Vec<String> = self.theme_problems.clone();
        notes.extend(self.settings_problem.clone());
        notes.extend(self.keymap_problem.clone());
        modal(t, 560.0).child(
            div()
                .p(px(t.pad))
                .flex()
                .flex_col()
                .child(div().text_size(px(17.0)).text_color(c(t.text[0])).pb_2().child("Settings"))
                .child(row("Theme", self.theme.name.to_string(), "Dark, light or high contrast. Change it from the palette (Ctrl K, type \"theme\"). A theme.toml next to ui.toml overrides single colours."))
                .child(row("Motion", motion, "System follows your desktop's animation setting. Reduced skips the arrival and all slides."))
                .child(row("Density", format!("{:?}", self.settings.density), "Comfortable or compact spacing."))
                .child(row("Run mode", "Managed by the daemon".into(), "Run mode, network features and retention are changed through the daemon, which asks your system's password dialog (polkit). Arrives with milestone 5."))
                .child(row("Keyboard", "keys.toml".into(), "Rebind any key in ~/.config/vigil/keys.toml, for example: \"ctrl-p\" = \"palette\". Press ? for every shortcut."))
                .children(notes.into_iter().map(|n| div().pt_2().text_size(px(12.0)).text_color(c(t.warn)).child(n))),
        )
    }

    fn shortcuts(&self) -> impl IntoElement {
        let t = &self.theme;
        let mut seen = vec![];
        let mut rows = vec![];
        for (_, a) in self.keymap.bindings() {
            if seen.contains(a) {
                continue;
            }
            seen.push(*a);
            let keys: Vec<String> = self.keymap.keys_for(*a).iter().map(|c| show_chord(c)).collect();
            rows.push(
                div()
                    .h(px(26.0))
                    .flex()
                    .items_center()
                    .child(div().w(px(150.0)).text_color(c(t.accent)).child(keys.join(" or ")))
                    .child(div().text_color(c(t.text[1])).truncate().child(a.describe())),
            );
        }
        modal(t, 720.0).child(
            div()
                .p(px(t.pad))
                .flex()
                .flex_col()
                .child(div().text_size(px(17.0)).text_color(c(t.text[0])).pb_2().child("Keyboard shortcuts"))
                .children(rows),
        )
    }

    fn arrival_layer(&self, t_ms: f32) -> impl IntoElement {
        let f = motion::arrival(t_ms, self.reduced());
        let theme = self.theme.clone();
        canvas(
            |_, _, _| {},
            move |b, _, w, cx| {
                w.paint_quad(fill(b, Hsla { a: 0.96 * f.backdrop, ..c(Rgba::rgb(0x0c0910)) }));
                let ctr = b.center();
                // A faint grid that fades in from the centre.
                let reach = f.grid_reach * f32::from(b.size.width.max(b.size.height)) * 0.6;
                let mut grid = PathBuilder::stroke(px(1.0));
                let step = 32.0;
                let n = (reach / step) as i32;
                for k in -n..=n {
                    let d = k as f32 * step;
                    let half = (reach * reach - d * d).max(0.0).sqrt();
                    grid.move_to(point(ctr.x + px(d), ctr.y - px(half)));
                    grid.line_to(point(ctr.x + px(d), ctr.y + px(half)));
                    grid.move_to(point(ctr.x - px(half), ctr.y + px(d)));
                    grid.line_to(point(ctr.x + px(half), ctr.y + px(d)));
                }
                if let Ok(p) = grid.build() {
                    w.paint_path(p, ca(theme.live, f.grid_opacity));
                }
                // Two rings sweep out: ice, then orange.
                for (i, r) in f.rings.iter().enumerate() {
                    let rad = 42.0 * r.radius;
                    let col = if i == 0 { theme.live_hi } else { theme.accent };
                    w.paint_quad(quad(
                        Bounds::new(point(ctr.x - px(rad), ctr.y - px(rad)), size(px(2.0 * rad), px(2.0 * rad))),
                        px(rad),
                        Hsla::transparent_black(),
                        px(1.5),
                        ca(col, r.opacity),
                        BorderStyle::Solid,
                    ));
                }
                paint_mark(w, ctr, 2.625, &f.faces, f.core_scale);
                // VIGIL resolves from wide tracking (blur is drawn as extra transparency).
                let font_size = 13.0;
                let letters = "VIGIL";
                let tracking = f.word_tracking * font_size;
                let font = w.text_style().font();
                let shaped: Vec<_> = letters
                    .chars()
                    .map(|ch| {
                        let run = TextRun {
                            len: ch.len_utf8(),
                            font: font.clone(),
                            color: ca(theme.text[0], f.word_opacity * (1.0 - f.word_blur / 12.0)),
                            background_color: None,
                            underline: None,
                            strikethrough: None,
                        };
                        w.text_system().shape_line(SharedString::from(ch.to_string()), px(font_size), &[run], None)
                    })
                    .collect();
                let total: f32 = shaped.iter().map(|l| f32::from(l.width) + tracking).sum::<f32>() - tracking;
                let mut x = f32::from(ctr.x) - total / 2.0;
                for line in shaped {
                    let wdt = f32::from(line.width);
                    let _ = line.paint(point(px(x), ctr.y + px(78.0)), px(18.0), TextAlign::Left, None, w, cx);
                    x += wdt + tracking;
                }
            },
        )
        .absolute()
        .top_0()
        .left_0()
        .size_full()
    }
}

/// A centred card above a dimmed backdrop.
fn modal(t: &Theme, width: f32) -> gpui::Div {
    div()
        .w(px(width))
        .max_h(px(620.0))
        .overflow_hidden()
        .rounded(px(t.radius))
        .bg(c(t.bg[2]))
        .border_1()
        .border_color(c(t.line[1]))
        .shadow_lg()
        .flex()
        .flex_col()
}

/// The Vigil mark: an isometric cube (three faces) with an orange core.
/// `scale` maps the mark's 32-unit view box to pixels.
fn paint_mark(w: &mut Window, ctr: Point<Pixels>, scale: f32, faces: &[motion::Face; 3], core_scale: f32) {
    const POLYS: [(&[(f32, f32)], u32); 3] = [
        (&[(16.0, 4.0), (26.4, 10.0), (16.0, 16.0), (5.6, 10.0)], 0x9fe3df),
        (&[(5.6, 10.0), (16.0, 16.0), (16.0, 28.0), (5.6, 22.0)], 0x3f9a95),
        (&[(26.4, 10.0), (16.0, 16.0), (16.0, 28.0), (26.4, 22.0)], 0x5dbdb9),
    ];
    for (i, (pts, col)) in POLYS.iter().enumerate() {
        let f = faces[i];
        if f.opacity <= 0.0 {
            continue;
        }
        let at = |(x, y): (f32, f32)| {
            let (sx, sy) = (16.0 + (x - 16.0) * f.scale + f.dx / 2.625, 16.0 + (y - 16.0) * f.scale + f.dy / 2.625);
            point(ctr.x + px((sx - 16.0) * scale), ctr.y + px((sy - 16.0) * scale))
        };
        let mut p = PathBuilder::fill();
        p.move_to(at(pts[0]));
        for q in &pts[1..] {
            p.line_to(at(*q));
        }
        p.close();
        if let Ok(path) = p.build() {
            w.paint_path(path, ca(Rgba::rgb(*col), f.opacity));
        }
    }
    if core_scale > 0.0 {
        let r = 2.2 * core_scale * scale;
        w.paint_quad(
            fill(
                Bounds::new(point(ctr.x - px(r), ctr.y - px(r)), size(px(2.0 * r), px(2.0 * r))),
                c(Rgba::rgb(0xff9f43)),
            )
            .corner_radii(px(r)),
        );
    }
}

impl Render for Vigil {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.first_frame.is_none() {
            let d = self.started.elapsed();
            self.first_frame = Some(d);
            if self.measure_startup {
                use std::io::Write;
                println!("{{\"first_frame_ms\": {:.1}}}", d.as_secs_f64() * 1000.0);
                let _ = std::io::stdout().flush();
                std::process::exit(0);
            }
        }
        let t = self.theme.clone();
        // Animate only while something moves: never repaint at frame rate while idle.
        let marker_moving = !self.reduced() && self.marker.2.elapsed() < Duration::from_millis(500);
        let arrival_ms = self.arrival.map(|t0| t0.elapsed().as_secs_f32() * 1000.0);
        if let Some(ms) = arrival_ms {
            if ms >= motion::ARRIVAL_MS {
                self.arrival = None;
                self.arrived = Some(Instant::now());
            }
        }
        let cards_rising = self.arrived.is_some_and(|a| a.elapsed() < Duration::from_millis(600));
        let toast_live = self.toast.as_ref().is_some_and(|(_, at)| at.elapsed() < Duration::from_secs(4));
        if marker_moving || self.arrival.is_some() || cards_rising {
            window.request_animation_frame();
        }
        let overlay = match self.overlay {
            Overlay::None => None,
            Overlay::Palette => Some(self.palette().into_any_element()),
            Overlay::Settings => Some(self.settings_sheet().into_any_element()),
            Overlay::Shortcuts => Some(self.shortcuts().into_any_element()),
        };
        let pending = self.keymap.pending().iter().map(|k| k.to_string()).collect::<Vec<_>>().join(" ");
        div()
            .size_full()
            .relative()
            .flex()
            .bg(c(t.bg[0]))
            .text_color(c(t.text[0]))
            .text_size(px(13.0))
            .font_family(t.ui_fonts[1])
            .track_focus(&self.focus)
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, _w, cx| this.on_key(ev, cx)))
            .child(self.rail(cx))
            .child(div().flex_1().h_full().flex().flex_col().child(self.top_bar()).child(self.content()))
            .when_some(overlay, |d, o| {
                d.child(
                    div()
                        .absolute()
                        .top_0()
                        .left_0()
                        .size_full()
                        .bg(Hsla { a: 0.55, ..c(Rgba::rgb(0x000000)) })
                        .flex()
                        .justify_center()
                        .items_start()
                        .pt(px(90.0))
                        .child(o),
                )
            })
            .when(!pending.is_empty(), |d| {
                d.child(
                    div()
                        .absolute()
                        .bottom(px(16.0))
                        .right(px(16.0))
                        .px_3()
                        .py_1()
                        .rounded(px(t.radius_sm))
                        .bg(c(t.bg[3]))
                        .text_color(c(t.text[1]))
                        .child(format!("{pending} …")),
                )
            })
            .when(toast_live, |d| {
                let text = self.toast.as_ref().map(|(s, _)| s.clone()).unwrap_or_default();
                d.child(
                    div()
                        .absolute()
                        .bottom(px(16.0))
                        .left(px(t.rail_width + 16.0))
                        .px_3()
                        .py_2()
                        .rounded(px(t.radius_sm))
                        .bg(c(t.bg[3]))
                        .border_1()
                        .border_color(c(t.line[1]))
                        .text_color(c(t.text[0]))
                        .child(text),
                )
            })
            .when_some(arrival_ms.filter(|_| self.arrival.is_some()), |d, ms| d.child(self.arrival_layer(ms)))
    }
}

fn main() {
    let started = Instant::now();
    gpui_platform::application().with_assets(icons::Assets).run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(1280.0), px(800.0)), cx);
        let window = cx
            .open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    focus: true,
                    app_id: Some("org.vigil.Vigil".into()),
                    ..Default::default()
                },
                move |window, cx| {
                    window.set_window_title("Vigil");
                    cx.new(|cx| {
                        let focus = cx.focus_handle();
                        focus.focus(window, cx);
                        Vigil::new(focus, started)
                    })
                },
            )
            .expect("open the window");
        // Theme hot-reload and toast expiry: look once a second, repaint only on change.
        let _ = window.update(cx, |_, _, cx| {
            cx.spawn(async move |this, cx| {
                let mut last_mtime = None;
                loop {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    let mtime = config_dir()
                        .and_then(|d| std::fs::metadata(d.join("theme.toml")).ok())
                        .and_then(|m| m.modified().ok());
                    let changed = mtime != last_mtime;
                    last_mtime = mtime;
                    let ok = this.update(cx, |v: &mut Vigil, cx| {
                        if changed {
                            v.reload_theme();
                        }
                        let expired = v.toast.as_ref().is_some_and(|(_, at)| at.elapsed() > Duration::from_secs(4));
                        if expired {
                            v.toast = None;
                        }
                        if changed || expired {
                            cx.notify();
                        }
                    });
                    if ok.is_err() {
                        break;
                    }
                }
            })
            .detach();
        });
        cx.activate(true);
    });
}
