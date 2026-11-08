//! The Vigil app.
//!
//! A left rail with every area, a top bar, and the areas themselves, fed live by the
//! daemon (src/live.rs). The command palette (Ctrl K), Settings (,), the shortcut sheet
//! (?), and the arrival on the Vigil mark (or g h), which also plays on launch.
//!
//! Everything that does not need a toolkit (keymap, palette ranking, motion, theme,
//! settings) lives in `vigil-ui-core` and is tested there. The views are in
//! src/views.rs, the mark and the arrival in src/mark.rs.
//!
//! Flags: `--bus system|session|address=...` (default: find the daemon), `--no-arrival`,
//! `--measure-startup` (print the time to the first frame and exit).

mod icons;
mod live;
mod mark;
mod ui;
mod views;

use gpui::{
    canvas, div, prelude::*, px, size, AnimationExt, App, Bounds, ClickEvent, ClipboardItem, Context, FocusHandle,
    Hsla, KeyDownEvent, Pixels, Render, Window, WindowBounds, WindowOptions,
};
use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};
use ui::{c, ca, id};
use vigil_store::StoredConnection;
use vigil_ui_core::areas::{info, AREAS};
use vigil_ui_core::keymap::{show_chord, Action, Key, Keymap, Outcome};
use vigil_ui_core::motion::{self, MarkFrame, MotionPref, Spring};
use vigil_ui_core::palette::{self, Entry, Kind};
use vigil_ui_core::settings::{config_dir, Density, UiSettings, View};
use vigil_ui_core::theme::{self, Rgba, Theme};

/// Where the rail logo sits (centre and circumradius): the arrival lands here.
pub const RAIL_LOGO: (f32, f32, f32) = (34.0, 34.0, 12.5);
pub const DETAIL_W: f32 = 400.0;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Overlay {
    None,
    Palette,
    Settings,
    Shortcuts,
}

pub enum Conn {
    Looking,
    Connected(String),
    Failed(String),
}

/// What is selected in the current list (for the detail panel, j/k and Enter).
#[derive(Clone, PartialEq, Debug)]
pub enum Sel {
    Proc(u32),
    Program(String),
}

pub struct Vigil {
    pub theme: Theme,
    pub notes: Vec<String>,
    pub settings: UiSettings,
    pub keymap: Keymap,
    pub area: usize,
    pub tab: Vec<usize>,
    history: Vec<usize>,
    future: Vec<usize>,
    /// Changes on every navigation, so entrances replay.
    pub nav: u64,
    pub overlay: Overlay,
    pub overlay_n: u64,
    closing: Option<(Overlay, Instant)>,
    pub query: String,
    pub pick: usize,
    entries: Vec<Entry>,
    marker: (f32, f32, Instant),
    pub arrival: Option<Instant>,
    pub arrived: Option<Instant>,
    toast: Option<(String, Instant)>,
    toast_n: u64,
    focus: FocusHandle,
    started: Instant,
    first_frame: Option<Duration>,
    measure_startup: bool,
    desktop_reduced: bool,
    pub user: String,
    // Live data.
    rx: Receiver<live::Msg>,
    req: Sender<live::Req>,
    pub conn: Conn,
    pub data: Option<live::Snapshot>,
    pub updates: u64,
    pub last_update: Option<Instant>,
    pub paused: bool,
    pub at: Option<(f64, Vec<StoredConnection>)>,
    pub at_asked: Option<f64>,
    // Lists and selection.
    pub sel: Option<Sel>,
    pub cursor: usize,
    pub filter: String,
    pub filter_focus: bool,
    pub map_bounds: Rc<Cell<Option<Bounds<Pixels>>>>,
    /// Rolling numbers: key -> (from, to, since).
    counters: HashMap<&'static str, (f32, f32, Instant)>,
    pub utc_offset_s: i64,
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

fn arg(name: &str) -> Option<String> {
    let mut it = std::env::args();
    while let Some(a) = it.next() {
        if a == name {
            return it.next();
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

impl Vigil {
    fn new(focus: FocusHandle, started: Instant, utc_offset_s: i64) -> Self {
        let dir = config_dir();
        let mut notes = vec![];
        let (settings, problem) = dir.as_ref().map(|d| UiSettings::load(&d.join("ui.toml"))).unwrap_or_default();
        notes.extend(problem);
        let keymap = match dir.as_ref().and_then(|d| std::fs::read_to_string(d.join("keys.toml")).ok()) {
            Some(text) => Keymap::with_overrides(&text).unwrap_or_else(|e| {
                notes.push(format!("keys.toml ignored: {e}"));
                Keymap::default()
            }),
            None => Keymap::default(),
        };
        let (rx, req) = live::spawn(arg("--bus").or_else(|| std::env::var("VIGIL_BUS").ok()));
        let desktop_reduced = desktop_reduced_motion();
        let no_arrival = std::env::args().any(|a| a == "--no-arrival" || a == "--measure-startup");
        let mut v = Vigil {
            theme: theme::by_name(&settings.theme),
            notes,
            settings,
            keymap,
            area: 0,
            tab: vec![0; AREAS.len()],
            history: vec![],
            future: vec![],
            nav: 0,
            overlay: Overlay::None,
            overlay_n: 0,
            closing: None,
            query: String::new(),
            pick: 0,
            entries: vec![],
            marker: (0.0, 0.0, Instant::now()),
            arrival: None,
            arrived: Some(Instant::now()),
            toast: None,
            toast_n: 0,
            focus,
            started,
            first_frame: None,
            measure_startup: std::env::args().any(|a| a == "--measure-startup"),
            desktop_reduced,
            user: std::env::var("USER").unwrap_or_default(),
            rx,
            req,
            conn: Conn::Looking,
            data: None,
            updates: 0,
            last_update: None,
            paused: false,
            at: None,
            at_asked: None,
            sel: None,
            cursor: 0,
            filter: String::new(),
            filter_focus: false,
            map_bounds: Rc::new(Cell::new(None)),
            counters: HashMap::new(),
            utc_offset_s,
        };
        v.reload_theme();
        v.entries = v.palette_entries();
        if !no_arrival && !v.reduced() {
            v.arrival = Some(Instant::now());
            v.arrived = None;
        }
        v
    }

    pub fn reduced(&self) -> bool {
        motion::reduced(self.settings.motion, self.desktop_reduced)
    }

    fn reload_theme(&mut self) {
        let base = theme::by_name(&self.settings.theme);
        let file = config_dir().and_then(|d| std::fs::read_to_string(d.join("theme.toml")).ok());
        let (t, problems) = match file {
            Some(text) => theme::with_overrides(base, &text),
            None => (base, vec![]),
        };
        self.theme = t;
        self.notes.retain(|n| !n.starts_with("theme"));
        self.notes.extend(problems);
    }

    fn save_settings(&mut self) {
        if let Some(d) = config_dir() {
            if let Err(e) = self.settings.save(&d.join("ui.toml")) {
                self.say(format!("Could not save settings: {e}"));
            }
        }
    }

    pub fn say(&mut self, text: impl Into<String>) {
        self.toast = Some((text.into(), Instant::now()));
        self.toast_n += 1;
    }

    pub fn copy(&mut self, text: String, what: &str, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.say(format!("Copied {what}"));
    }

    pub fn keys_hint(&self, a: Action) -> String {
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
        for a in [Action::Settings, Action::Shortcuts, Action::Arrival, Action::ToggleExpert, Action::PlayPause] {
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
            ("Motion: System", "motion:system"),
            ("Motion: Full", "motion:full"),
            ("Motion: Reduced", "motion:reduced"),
            ("Density: Comfortable", "density:comfortable"),
            ("Density: Compact", "density:compact"),
        ] {
            out.push(Entry { title: name.into(), hint: "setting".into(), kind: Kind::Setting, id: id.into() });
        }
        // Live entries: programs and processes from the last look.
        if let Some(d) = &self.data {
            for p in d.procs.processes.iter().take(400) {
                out.push(Entry {
                    title: p.name.clone(),
                    hint: format!("pid {} · {}", p.pid, p.user),
                    kind: Kind::Process,
                    id: format!("proc:{}", p.pid),
                });
            }
            let mut seen = std::collections::BTreeSet::new();
            for s in &d.net.sockets {
                if s.kind == "connection" && seen.insert(s.remote_ip.clone()) {
                    out.push(Entry {
                        title: s.remote_ip.clone(),
                        hint: s.program.clone().unwrap_or_default(),
                        kind: Kind::Address,
                        id: format!("addr:{}", s.remote_ip),
                    });
                }
            }
        }
        out
    }

    pub fn go(&mut self, area: usize) {
        if area == self.area {
            return;
        }
        self.history.push(self.area);
        self.future.clear();
        self.move_to(area);
    }

    fn move_to(&mut self, area: usize) {
        let now = self.marker_pos();
        self.marker = (now, area as f32, Instant::now());
        self.area = area;
        self.nav += 1;
        self.sel = None;
        self.cursor = 0;
        self.filter_focus = false;
        if area == 0 {
            self.arrived = Some(Instant::now());
        }
    }

    pub fn set_tab(&mut self, area: usize, tab: usize) {
        self.go(area);
        if self.tab[area] != tab {
            self.tab[area] = tab;
            self.nav += 1;
            self.sel = None;
            self.cursor = 0;
        }
    }

    fn marker_pos(&self) -> f32 {
        let (from, to, t0) = self.marker;
        if self.reduced() {
            return to;
        }
        from + (to - from) * Spring::SNAPPY.value(t0.elapsed().as_secs_f32())
    }

    pub fn open_overlay(&mut self, o: Overlay) {
        if self.overlay != Overlay::None && self.overlay != o {
            self.closing = Some((self.overlay, Instant::now()));
        }
        self.overlay = o;
        self.overlay_n += 1;
        if o == Overlay::Palette {
            self.query.clear();
            self.pick = 0;
            self.entries = self.palette_entries();
        }
    }

    pub fn close_overlay(&mut self) {
        if self.overlay != Overlay::None {
            self.closing = Some((self.overlay, Instant::now()));
            self.overlay = Overlay::None;
        }
    }

    pub fn choose(&mut self, id: &str) {
        let parts: Vec<&str> = id.splitn(3, ':').collect();
        self.close_overlay();
        match parts.as_slice() {
            ["area", i] => self.go(i.parse().unwrap_or(0)),
            ["tab", i, t] => self.set_tab(i.parse().unwrap_or(0), t.parse().unwrap_or(0)),
            ["action", name] => {
                if let Some(a) = Action::parse(name) {
                    self.act(a);
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
            ["proc", pid] => {
                self.set_tab(2, 1);
                self.sel = pid.parse().ok().map(Sel::Proc);
            }
            ["addr", ip] => {
                self.set_tab(1, 1);
                self.filter = (*ip).to_string();
            }
            _ => {}
        }
    }

    pub fn time_machine(&mut self, t: f64) {
        self.at_asked = Some(t);
        let _ = self.req.send(live::Req::At(t));
    }

    pub fn act(&mut self, a: Action) {
        match a {
            Action::Palette => self.open_overlay(Overlay::Palette),
            Action::GoArea(i) => self.go(i),
            Action::Arrival => {
                self.close_overlay();
                if self.area != 0 {
                    self.go(0);
                }
                if self.reduced() {
                    self.arrived = Some(Instant::now());
                } else {
                    self.arrival = Some(Instant::now());
                    self.arrived = None;
                }
            }
            Action::Back => {
                if self.overlay != Overlay::None {
                    self.close_overlay();
                } else if self.filter_focus {
                    self.filter_focus = false;
                } else if self.sel.is_some() {
                    self.sel = None;
                } else if !self.filter.is_empty() {
                    self.filter.clear();
                } else if let Some(prev) = self.history.pop() {
                    self.future.push(self.area);
                    self.move_to(prev);
                }
            }
            Action::HistoryBack => {
                if let Some(prev) = self.history.pop() {
                    self.future.push(self.area);
                    self.move_to(prev);
                }
            }
            Action::HistoryForward => {
                if let Some(next) = self.future.pop() {
                    self.history.push(self.area);
                    self.move_to(next);
                }
            }
            Action::PrevTab | Action::NextTab => {
                let n = info(AREAS[self.area].area).tabs.len();
                let t = self.tab[self.area];
                let next = if a == Action::NextTab { (t + 1) % n } else { (t + n - 1) % n };
                self.set_tab(self.area, next);
            }
            Action::Settings => {
                if self.overlay == Overlay::Settings {
                    self.close_overlay()
                } else {
                    self.open_overlay(Overlay::Settings)
                }
            }
            Action::Shortcuts => {
                if self.overlay == Overlay::Shortcuts {
                    self.close_overlay()
                } else {
                    self.open_overlay(Overlay::Shortcuts)
                }
            }
            Action::ToggleExpert => {
                let v = self.settings.toggle_view(AREAS[self.area].id);
                self.save_settings();
                self.nav += 1;
                self.say(format!("{}: {}", AREAS[self.area].name, if v == View::Expert { "Expert" } else { "Guided" }));
            }
            Action::Filter => {
                self.filter_focus = true;
                if !matches!(self.area, 1 | 2 | 8) {
                    self.set_tab(2, 1);
                }
            }
            Action::PlayPause => {
                self.paused = !self.paused;
                self.say(if self.paused { "Paused: the view stays as it is" } else { "Live again" });
            }
            Action::TimeMachine => self.set_tab(1, 3),
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
            Action::Down | Action::Up => {
                let items = self.list_items();
                if items.is_empty() {
                    return;
                }
                let cur = items.iter().position(|s| Some(s) == self.sel.as_ref()).unwrap_or(self.cursor);
                let next = if a == Action::Down { (cur + 1).min(items.len() - 1) } else { cur.saturating_sub(1) };
                self.cursor = next;
                self.sel = Some(items[next].clone());
            }
            Action::Open => {
                if self.sel.is_none() {
                    if let Some(first) = self.list_items().into_iter().next() {
                        self.sel = Some(first);
                    }
                }
            }
            Action::Pivot => match self.sel.clone() {
                Some(Sel::Proc(pid)) => {
                    self.set_tab(1, 1);
                    self.filter = format!("pid:{pid}");
                }
                Some(Sel::Program(key)) => {
                    let pid = self.data.as_ref().and_then(|d| {
                        d.net.sockets.iter().find(|s| s.program.as_deref() == Some(&key)).and_then(|s| s.pid)
                    });
                    self.set_tab(2, 1);
                    self.sel = pid.map(Sel::Proc);
                }
                None => self.say("Select a process or a program first, then press p to pivot"),
            },
            Action::Copy | Action::Run | Action::SetAside | Action::AddToCase => {
                self.say(format!("{}: arrives with findings and Run mode (milestones 3 and 5)", a.describe()));
            }
        }
    }

    fn on_key(&mut self, ev: &KeyDownEvent, cx: &mut Context<Self>) {
        if let Some(t0) = self.arrival {
            if t0.elapsed().as_secs_f32() * 1000.0 < motion::ARRIVAL_MS {
                self.arrival = None;
                self.arrived = Some(Instant::now());
                cx.notify();
                return;
            }
        }
        let key = key_from(ev);
        // Copy works on the selection directly (it needs the clipboard).
        if key.key == "c" && !key.ctrl && self.overlay == Overlay::None && !self.filter_focus {
            if let Some((text, what)) = self.selection_text() {
                self.copy(text, &what, cx);
                cx.notify();
                return;
            }
        }
        let palette = self.overlay == Overlay::Palette;
        let typing = palette || self.filter_focus;
        if typing && !key.ctrl && !key.alt {
            let target = if palette { &mut self.query } else { &mut self.filter };
            let handled = match key.key.as_str() {
                "backspace" => {
                    target.pop();
                    true
                }
                "space" => {
                    target.push(' ');
                    true
                }
                k if k.chars().count() == 1 => {
                    target.push_str(k);
                    true
                }
                _ => false,
            };
            if handled {
                self.pick = 0;
                self.cursor = 0;
                cx.notify();
                return;
            }
        }
        if self.filter_focus && key.key == "enter" {
            self.filter_focus = false;
            cx.notify();
            return;
        }
        let typing_now = typing && !matches!(key.key.as_str(), "down" | "up" | "enter");
        if let Outcome::Action(a) = self.keymap.feed(key, typing_now) {
            self.act(a);
        }
        cx.notify();
    }

    /// The text `c` copies for the selection, and what to call it.
    fn selection_text(&self) -> Option<(String, String)> {
        let d = self.data.as_ref()?;
        match self.sel.as_ref()? {
            Sel::Proc(pid) => {
                let p = d.procs.processes.iter().find(|p| p.pid == *pid)?;
                Some((p.cmdline.join(" "), "the command line".into()))
            }
            Sel::Program(key) => Some((key.clone(), "the program path".into())),
        }
    }

    /// Pull whatever the bus thread sent. Returns true if anything changed.
    fn drain(&mut self) -> bool {
        let mut changed = false;
        while let Ok(m) = self.rx.try_recv() {
            changed = true;
            match m {
                live::Msg::Connected(bus) => self.conn = Conn::Connected(bus),
                live::Msg::Failed(e) => self.conn = Conn::Failed(e),
                live::Msg::Data(s) => {
                    if !self.paused {
                        self.data = Some(*s);
                        self.updates += 1;
                        self.last_update = Some(Instant::now());
                    }
                }
                live::Msg::At(t, rows) => self.at = Some((t, rows)),
            }
        }
        changed
    }

    /// Rolling numbers: set targets from the data; return true while any is moving.
    fn tick_counters(&mut self) -> bool {
        let targets: Vec<(&'static str, f32)> = match &self.data {
            Some(d) => {
                let out = d.net.sockets.iter().filter(|s| s.kind == "connection" && s.direction == "out").count();
                let progs: std::collections::BTreeSet<_> =
                    d.net.sockets.iter().filter(|s| s.kind == "connection").filter_map(|s| s.program.clone()).collect();
                vec![
                    ("procs", d.procs.processes.len() as f32),
                    ("out", out as f32),
                    ("programs", progs.len() as f32),
                    ("dests", d.status.store.destinations_seen as f32),
                    ("mem", (d.status.rss_kb as f32) / 1024.0),
                ]
            }
            None => vec![],
        };
        let now = Instant::now();
        let mut moving = false;
        for (k, target) in targets {
            let shown = self.counter(k);
            let e = self.counters.entry(k).or_insert((0.0, target, now));
            if (e.1 - target).abs() > f32::EPSILON {
                *e = (shown, target, now);
            }
            if e.2.elapsed().as_secs_f32() * 1000.0 < motion::COUNTER_MS {
                moving = true;
            }
        }
        moving && !self.reduced()
    }

    pub fn counter(&self, k: &str) -> f32 {
        self.counters.get(k).map_or(0.0, |(from, to, t0)| {
            motion::tween(*from, *to, t0.elapsed().as_secs_f32() * 1000.0, motion::COUNTER_MS, self.reduced())
        })
    }

    // ---- the shell ------------------------------------------------------------------------

    fn rail(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = &self.theme;
        let item_h = 54.0;
        let top = 68.0;
        let marker_y = top + self.marker_pos() * item_h;
        let logo_hidden = self.arrival.is_some();
        let mut items = vec![];
        for (i, a) in AREAS.iter().enumerate() {
            let here = i == self.area;
            let col = if here { t.text[0] } else { t.text[2] };
            let hover_bg = ca(Rgba(0xffffff0d), 1.0);
            items.push(
                div()
                    .id(id("rail", i as u64))
                    .h(px(item_h))
                    .w_full()
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .gap(px(3.0))
                    .cursor_pointer()
                    .hover(move |s| s.bg(hover_bg))
                    .active(|s| s.opacity(0.7))
                    .child(gpui::svg().path(format!("icons/{}.svg", a.id)).size(px(20.0)).text_color(if here {
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
                    .w_full()
                    .cursor_pointer()
                    .child(
                        canvas(
                            |_, _, _| {},
                            move |b, _, w, _| {
                                if !logo_hidden {
                                    let (x, y, r) = RAIL_LOGO;
                                    mark::paint(w, b.origin, &MarkFrame::at_rest(x, y, r));
                                }
                            },
                        )
                        .size_full(),
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
                    .top(px(marker_y + 13.0))
                    .w(px(3.0))
                    .h(px(item_h - 26.0))
                    .rounded_r(px(2.0))
                    .bg(c(t.accent)),
            )
            .children(items)
            .child(div().flex_1())
            .child(
                div()
                    .id("rail-keys")
                    .h(px(44.0))
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .hover(|s| s.opacity(0.75))
                    .child(gpui::svg().path("icons/keys.svg").size(px(19.0)).text_color(c(t.text[2])))
                    .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                        this.act(Action::Shortcuts);
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .id("rail-gear")
                    .h(px(44.0))
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .hover(|s| s.opacity(0.75))
                    .child(gpui::svg().path("icons/gear.svg").size(px(19.0)).text_color(c(t.text[1])))
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

    fn top_bar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = &self.theme;
        let area = self.area;
        let a = &AREAS[area];
        let mut tabs = vec![];
        for (i, name) in a.tabs.iter().enumerate() {
            let on = i == self.tab[area];
            let accent = t.accent;
            tabs.push(
                div()
                    .id(id("tab", i as u64))
                    .px(px(12.0))
                    .h_full()
                    .flex()
                    .items_center()
                    .relative()
                    .cursor_pointer()
                    .text_color(if on { c(t.text[0]) } else { c(t.text[2]) })
                    .hover(|s| s.opacity(0.85))
                    .child(*name)
                    .when(on, move |d| {
                        d.child(
                            div()
                                .absolute()
                                .bottom_0()
                                .left(px(10.0))
                                .right(px(10.0))
                                .h(px(2.0))
                                .rounded(px(1.0))
                                .bg(c(accent)),
                        )
                    })
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.set_tab(area, i);
                        cx.notify();
                    })),
            );
        }
        let view = if self.settings.view(a.id) == View::Expert { "Expert" } else { "Guided" };
        let (dot, status) = match &self.conn {
            Conn::Connected(bus) if self.paused => (t.warn, format!("Paused · {bus} daemon")),
            Conn::Connected(bus) => (t.ok, format!("Live · {bus} daemon")),
            Conn::Looking => (t.text[2], "Looking for the daemon…".to_string()),
            Conn::Failed(_) => (t.danger, "Daemon not running".to_string()),
        };
        let pulse = self.updates;
        let reduced = self.reduced();
        div()
            .h(px(54.0))
            .flex_none()
            .flex()
            .items_center()
            .gap(px(14.0))
            .px(px(t.pad))
            .border_b_1()
            .border_color(c(t.line[0]))
            .child(div().text_size(px(17.0)).text_color(c(t.text[0])).child(a.name))
            .child(div().h_full().flex().children(tabs))
            .child(div().flex_1())
            .child(
                div()
                    .id("view-toggle")
                    .px(px(8.0))
                    .py(px(4.0))
                    .rounded(px(t.radius_sm))
                    .cursor_pointer()
                    .hover(|s| s.opacity(0.8))
                    .text_size(px(12.0))
                    .text_color(c(t.text[2]))
                    .child(view)
                    .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                        this.act(Action::ToggleExpert);
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .id("live")
                    .flex()
                    .items_center()
                    .gap(px(7.0))
                    .px(px(8.0))
                    .py(px(4.0))
                    .rounded(px(t.radius_sm))
                    .cursor_pointer()
                    .hover(|s| s.opacity(0.8))
                    .text_size(px(12.0))
                    .text_color(c(t.text[2]))
                    .child(ui::enter(
                        div().size(px(7.0)).rounded_full().bg(c(dot)),
                        id("pulse", pulse),
                        0.0,
                        0.0,
                        reduced,
                    ))
                    .child(status)
                    .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                        this.act(Action::PlayPause);
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .id("jump")
                    .h(px(t.control_height))
                    .px(px(12.0))
                    .flex()
                    .items_center()
                    .gap(px(8.0))
                    .rounded(px(t.radius_sm))
                    .border_1()
                    .border_color(c(t.line[1]))
                    .text_color(c(t.text[1]))
                    .cursor_pointer()
                    .hover(|s| s.bg(ca(Rgba(0xffffff0a), 1.0)))
                    .active(|s| s.opacity(0.8))
                    .child(gpui::svg().path("icons/search.svg").size(px(15.0)).text_color(c(t.text[1])))
                    .child("Jump to…")
                    .child(ui::kbd(t, self.keys_hint(Action::Palette)))
                    .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                        this.act(Action::Palette);
                        cx.notify();
                    })),
            )
    }

    fn overlay_view(&self, o: Overlay, cx: &mut Context<Self>) -> gpui::AnyElement {
        match o {
            Overlay::Palette => self.palette_view(cx).into_any_element(),
            Overlay::Settings => self.settings_view(cx).into_any_element(),
            Overlay::Shortcuts => self.shortcuts_view().into_any_element(),
            Overlay::None => div().into_any_element(),
        }
    }

    fn palette_view(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = &self.theme;
        let hits = palette::search(&self.entries, &self.query, 12);
        let mut rows = vec![];
        for (n, h) in hits.iter().enumerate() {
            let e = &self.entries[h.index];
            let on = n == self.pick;
            let mut title = vec![];
            for (ci, ch) in e.title.chars().enumerate() {
                let hit = h.matched.contains(&ci);
                title.push(div().text_color(if hit { c(t.accent) } else { c(t.text[0]) }).child(ch.to_string()));
            }
            let entry_id = e.id.clone();
            rows.push(
                div()
                    .id(id("pal", n as u64))
                    .h(px(38.0))
                    .px(px(12.0))
                    .flex()
                    .items_center()
                    .gap(px(12.0))
                    .rounded(px(t.radius_sm))
                    .cursor_pointer()
                    .bg(if on { c(t.accent_soft) } else { ca(t.bg[2], 0.0) })
                    .hover(|s| s.bg(ca(Rgba(0xffffff0d), 1.0)))
                    .child(div().w(px(60.0)).text_size(px(11.0)).text_color(c(t.text[2])).child(e.kind.label()))
                    .child(div().flex().children(title))
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(c(t.text[2]))
                            .truncate()
                            .max_w(px(300.0))
                            .child(e.hint.clone()),
                    )
                    .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                        this.choose(&entry_id);
                        cx.notify();
                    })),
            );
        }
        let empty = hits.is_empty();
        modal(t, 660.0)
            .child(
                div()
                    .h(px(52.0))
                    .px(px(16.0))
                    .flex()
                    .items_center()
                    .gap(px(12.0))
                    .border_b_1()
                    .border_color(c(t.line[0]))
                    .child(gpui::svg().path("icons/search.svg").size(px(18.0)).text_color(c(t.text[1])))
                    .child(if self.query.is_empty() {
                        div().text_color(c(t.text[2])).child("Areas, tabs, processes, addresses, settings…")
                    } else {
                        div().text_size(px(15.0)).text_color(c(t.text[0])).child(format!("{}▏", self.query))
                    }),
            )
            .child(
                div()
                    .p(px(8.0))
                    .flex()
                    .flex_col()
                    .children(rows)
                    .when(empty, |d| d.child(div().p(px(14.0)).text_color(c(t.text[2])).child("Nothing matches."))),
            )
    }

    fn settings_view(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = &self.theme;
        let seg =
            |name: &'static str, options: &[(&'static str, &'static str)], current: &str, cx: &mut Context<Self>| {
                let mut opts = vec![];
                for (i, (value, label)) in options.iter().enumerate() {
                    let on = *value == current;
                    let target = format!("{name}:{value}");
                    opts.push(
                        div()
                            .id(ui::id2("seg", name.len() as u64, i as u64))
                            .px(px(11.0))
                            .h(px(26.0))
                            .flex()
                            .items_center()
                            .rounded(px(6.0))
                            .cursor_pointer()
                            .text_size(px(12.0))
                            .bg(if on { c(t.bg[4]) } else { ca(t.bg[4], 0.0) })
                            .text_color(if on { c(t.text[0]) } else { c(t.text[2]) })
                            .hover(|s| s.opacity(0.85))
                            .child(*label)
                            .on_click(cx.listener(move |this, _: &ClickEvent, _w, cx| {
                                this.choose(&target);
                                this.open_overlay(Overlay::Settings);
                                cx.notify();
                            })),
                    );
                }
                div().p(px(3.0)).rounded(px(8.0)).bg(c(t.bg[3])).flex().gap(px(2.0)).children(opts)
            };
        let row = |title: &str, help: &str, control: gpui::AnyElement| {
            div()
                .py(px(14.0))
                .flex()
                .flex_col()
                .gap(px(6.0))
                .border_b_1()
                .border_color(c(t.line[0]))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .child(div().text_color(c(t.text[0])).child(title.to_string()))
                        .child(div().flex_1())
                        .child(control),
                )
                .child(div().text_size(px(12.0)).text_color(c(t.text[2])).child(help.to_string()))
        };
        let motion = match self.settings.motion {
            MotionPref::System => "system",
            MotionPref::Full => "full",
            MotionPref::Reduced => "reduced",
        };
        let density = if self.settings.density == Density::Compact { "compact" } else { "comfortable" };
        let theme_name = self.settings.theme.clone();
        let theme_seg =
            seg("theme", &[("dark", "Dark"), ("light", "Light"), ("high-contrast", "High contrast")], &theme_name, cx);
        let motion_seg = seg("motion", &[("system", "System"), ("full", "Full"), ("reduced", "Reduced")], motion, cx);
        let density_seg = seg("density", &[("comfortable", "Comfortable"), ("compact", "Compact")], density, cx);
        let close =
            ui::button(t, "settings-close", "Done", false).on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                this.close_overlay();
                cx.notify();
            }));
        div()
            .w(px(460.0))
            .h_full()
            .bg(c(t.bg[2]))
            .border_l_1()
            .border_color(c(t.line[1]))
            .p(px(t.pad))
            .flex()
            .flex_col()
            .child(div().flex().items_center().pb(px(8.0)).child(div().text_size(px(18.0)).text_color(c(t.text[0])).child("Settings")).child(div().flex_1()).child(close))
            .child(row("Theme", "A theme.toml next to ui.toml can change single colours; Vigil reloads it as you save.", theme_seg.into_any_element()))
            .child(row(
                "Motion",
                &format!("System follows your desktop ({} now). Reduced skips the arrival and every slide.", if self.desktop_reduced { "reduced" } else { "full" }),
                motion_seg.into_any_element(),
            ))
            .child(row("Density", "Spacing in every view.", density_seg.into_any_element()))
            .child(row(
                "Run mode",
                "Run mode, network features and history are the daemon's settings, changed through your system's password dialog (polkit). Arrives with milestone 5.",
                ui::chip("Daemon", t.text[2]).into_any_element(),
            ))
            .child(row(
                "Keyboard",
                "Rebind any key in ~/.config/vigil/keys.toml, for example \"ctrl-p\" = \"palette\".",
                ui::kbd(t, "?").into_any_element(),
            ))
            .children(self.notes.iter().map(|n| div().pt(px(10.0)).text_size(px(12.0)).text_color(c(t.warn)).child(n.clone())))
    }

    fn shortcuts_view(&self) -> impl IntoElement {
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
                    .h(px(27.0))
                    .flex()
                    .items_center()
                    .child(div().w(px(170.0)).text_color(c(t.accent)).child(keys.join("  or  ")))
                    .child(div().text_color(c(t.text[1])).truncate().child(a.describe())),
            );
        }
        modal(t, 740.0).child(
            div()
                .p(px(t.pad))
                .flex()
                .flex_col()
                .child(div().text_size(px(18.0)).text_color(c(t.text[0])).pb(px(10.0)).child("Keyboard"))
                .children(rows),
        )
    }
}

/// A centred card above the dimmed app.
fn modal(t: &Theme, width: f32) -> gpui::Div {
    div()
        .w(px(width))
        .max_h(px(640.0))
        .overflow_hidden()
        .rounded(px(t.radius + 2.0))
        .bg(c(t.bg[2]))
        .border_1()
        .border_color(c(t.line[1]))
        .shadow_lg()
        .flex()
        .flex_col()
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
        self.drain();
        let t = self.theme.clone();
        let reduced = self.reduced();
        // Animate only while something moves: never repaint at frame rate while idle.
        let arrival_ms = self.arrival.map(|t0| t0.elapsed().as_secs_f32() * 1000.0);
        if arrival_ms.is_some_and(|ms| ms >= motion::ARRIVAL_MS) {
            self.arrival = None;
            self.arrived = Some(Instant::now());
        }
        let marker_moving = !reduced && self.marker.2.elapsed() < Duration::from_millis(700);
        let cards_rising = self.arrived.is_some_and(|a| a.elapsed() < Duration::from_millis(900));
        let closing_ms = self.closing.map(|(_, at)| at.elapsed().as_secs_f32() * 1000.0);
        if closing_ms.is_some_and(|ms| ms >= motion::OVERLAY_OUT_MS || reduced) {
            self.closing = None;
        }
        let counting = self.tick_counters();
        let map_live = !reduced && self.area == 1 && self.tab[1] == 0 && self.data.is_some();
        if marker_moving || self.arrival.is_some() || cards_rising || self.closing.is_some() || counting || map_live {
            window.request_animation_frame();
        }
        let toast_live = self.toast.as_ref().is_some_and(|(_, at)| at.elapsed() < Duration::from_millis(3200));

        let body = self.area_view(cx);
        let mut root = div()
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
            .child(div().flex_1().h_full().min_w(px(0.0)).flex().flex_col().child(self.top_bar(cx)).child(body));

        // Overlays: the one opening (keyed animation), and the one closing (reverse, by hand).
        let layer = |o: Overlay, d: f32, content: gpui::AnyElement, cx: &mut Context<Self>| {
            let sheet = o == Overlay::Settings;
            div()
                .id(id("overlay", o as u64))
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .bg(Hsla { a: 0.5 * d, ..c(Rgba::rgb(0x000000)) })
                .flex()
                .when(sheet, |el| el.justify_end())
                .when(!sheet, |el| el.justify_center().items_start().pt(px(92.0)))
                .on_click(cx.listener(|this, _: &ClickEvent, _w, cx| {
                    this.close_overlay();
                    cx.notify();
                }))
                .child(
                    div()
                        .id("overlay-content")
                        .when(sheet, |el| el.h_full())
                        .opacity(d)
                        .relative()
                        .when(sheet, |el| el.left(px(40.0 * (1.0 - d))))
                        .when(!sheet, |el| el.top(px(-10.0 * (1.0 - d))))
                        .on_click(|_, _, cx| cx.stop_propagation())
                        .child(content),
                )
        };
        if let Some((o, _)) = self.closing {
            let d = 1.0 - motion::ease((closing_ms.unwrap_or(0.0) / motion::OVERLAY_OUT_MS).clamp(0.0, 1.0));
            let content = self.overlay_view(o, cx);
            root = root.child(layer(o, d, content, cx));
        }
        if self.overlay != Overlay::None {
            let o = self.overlay;
            let content = self.overlay_view(o, cx);
            let spring = Spring::SNAPPY.easing(motion::OVERLAY_IN_MS);
            let anim =
                gpui::Animation::new(Duration::from_millis(if reduced { 1 } else { motion::OVERLAY_IN_MS as u64 }))
                    .with_easing(spring);
            let base = layer(o, 1.0, content, cx);
            root = root
                .child(base.with_animation(id("open", self.overlay_n), anim, |el, d| el.opacity(d.clamp(0.0, 1.0))));
        }
        let pending = self.keymap.pending().iter().map(|k| k.to_string()).collect::<Vec<_>>().join(" ");
        if !pending.is_empty() {
            root = root.child(
                div()
                    .absolute()
                    .bottom(px(18.0))
                    .right(px(18.0))
                    .px(px(10.0))
                    .py(px(4.0))
                    .rounded(px(t.radius_sm))
                    .bg(c(t.bg[3]))
                    .text_color(c(t.text[1]))
                    .child(format!("{pending} …")),
            );
        }
        if toast_live {
            let text = self.toast.as_ref().map(|(s, _)| s.clone()).unwrap_or_default();
            root = root.child(ui::enter(
                div()
                    .absolute()
                    .bottom(px(20.0))
                    .left(px(t.rail_width + 20.0))
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(t.radius_sm))
                    .bg(c(t.bg[3]))
                    .border_1()
                    .border_color(c(t.line[1]))
                    .shadow_lg()
                    .text_color(c(t.text[0]))
                    .child(text),
                id("toast", self.toast_n),
                0.0,
                10.0,
                reduced,
            ));
        }
        if let Some(ms) = arrival_ms.filter(|_| self.arrival.is_some()) {
            let (x, y, r) = RAIL_LOGO;
            let land = motion::Landing { cx: x, cy: y, radius: r };
            let (bg, text) = (t.bg[0].0 >> 8, t.text[0].0 >> 8);
            root = root.child(
                canvas(|_, _, _| {}, move |b, _, w, cx| mark::paint_arrival(w, cx, b, ms, land, bg, text))
                    .absolute()
                    .top_0()
                    .left_0()
                    .size_full(),
            );
        }
        root
    }
}

fn main() {
    let started = Instant::now();
    // Read the local time zone before any thread starts (the only time it is safe).
    let utc_offset_s = time::UtcOffset::current_local_offset().map_or(0, |o| i64::from(o.whole_seconds()));
    gpui_platform::application().with_assets(icons::Assets).run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(1320.0), px(840.0)), cx);
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
                        Vigil::new(focus, started, utc_offset_s)
                    })
                },
            )
            .expect("open the window");
        // Live data and theme reloads: look a few times a second, repaint only on change.
        let _ = window.update(cx, |_, _, cx| {
            cx.spawn(async move |this, cx| {
                let mut last_mtime = None;
                let mut n = 0u32;
                loop {
                    cx.background_executor().timer(Duration::from_millis(120)).await;
                    n += 1;
                    let mtime = if n.is_multiple_of(8) {
                        config_dir()
                            .and_then(|d| std::fs::metadata(d.join("theme.toml")).ok())
                            .and_then(|m| m.modified().ok())
                    } else {
                        last_mtime
                    };
                    let theme_changed = mtime != last_mtime;
                    last_mtime = mtime;
                    let ok = this.update(cx, |v: &mut Vigil, cx| {
                        if theme_changed {
                            v.reload_theme();
                        }
                        let data = v.drain();
                        let expired =
                            v.toast.as_ref().is_some_and(|(_, at)| at.elapsed() > Duration::from_millis(3200));
                        if expired {
                            v.toast = None;
                        }
                        if data || theme_changed || expired {
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
