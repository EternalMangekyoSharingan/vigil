//! Keyboard: every action reachable without a mouse (docs/RUST_REWRITE.md 5.5).
//!
//! Bindings are written as text: `"ctrl-k"`, `"j"`, `"g h"` (a chord: g, then h). The
//! defaults live here; the user's overrides live in `~/.config/vigil/keys.toml`:
//!
//! ```toml
//! [bindings]
//! "ctrl-p" = "palette"     # add a binding
//! "x" = "none"             # remove one
//! ```
//!
//! [`Keymap::feed`] turns key presses into actions. While a text field has focus, only
//! bindings with a modifier (and Escape) are live, so typing "j" in the filter box types
//! a j.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;

use crate::areas::{Area, AREAS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    Palette,
    GoArea(usize),
    Arrival,
    Down,
    Up,
    Open,
    Back,
    PrevTab,
    NextTab,
    HistoryBack,
    HistoryForward,
    Filter,
    Shortcuts,
    Settings,
    Copy,
    Run,
    SetAside,
    AddToCase,
    Pivot,
    TimeMachine,
    PlayPause,
    ToggleExpert,
}

impl Action {
    /// The name used in keys.toml.
    pub fn name(self) -> String {
        match self {
            Action::GoArea(i) => format!("go-{}", AREAS[i].id),
            other => ACTION_NAMES.iter().find(|(a, _, _)| *a == other).map_or("?", |(_, n, _)| n).to_string(),
        }
    }

    /// What it does, for the shortcut sheet, the palette and tooltips.
    pub fn describe(self) -> String {
        match self {
            Action::GoArea(i) => format!("Go to {}", AREAS[i].name),
            other => ACTION_NAMES.iter().find(|(a, _, _)| *a == other).map_or("?", |(_, _, d)| d).to_string(),
        }
    }

    pub fn parse(name: &str) -> Option<Action> {
        if let Some(id) = name.strip_prefix("go-") {
            return AREAS.iter().position(|a| a.id == id).map(Action::GoArea);
        }
        ACTION_NAMES.iter().find(|(_, n, _)| *n == name).map(|(a, _, _)| *a)
    }

    pub fn area(area: Area) -> Action {
        Action::GoArea(AREAS.iter().position(|a| a.area == area).unwrap_or(0))
    }
}

const ACTION_NAMES: &[(Action, &str, &str)] = &[
    (
        Action::Palette,
        "palette",
        "Command palette: areas, tabs, findings, processes, addresses, files, actions, settings",
    ),
    (Action::Arrival, "home-arrival", "Home, with the arrival animation"),
    (Action::Down, "down", "Next item in the list"),
    (Action::Up, "up", "Previous item in the list"),
    (Action::Open, "open", "Open the selected item"),
    (Action::Back, "back", "Back, or close"),
    (Action::PrevTab, "prev-tab", "Previous tab"),
    (Action::NextTab, "next-tab", "Next tab"),
    (Action::HistoryBack, "history-back", "Back in history"),
    (Action::HistoryForward, "history-forward", "Forward in history"),
    (Action::Filter, "filter", "Filter this view"),
    (Action::Shortcuts, "shortcuts", "Show the keyboard shortcuts"),
    (Action::Settings, "settings", "Settings"),
    (Action::Copy, "copy", "Copy the selected command"),
    (Action::Run, "run", "Run the selected command (asks first; Run mode only)"),
    (Action::SetAside, "set-aside", "Set aside: Expected, Fixed or Not a problem, with a reason"),
    (Action::AddToCase, "add-to-case", "Add to a case"),
    (Action::Pivot, "pivot", "Pivot on the selected program, address, file or package"),
    (Action::TimeMachine, "time-machine", "Open the time machine at the selection's time"),
    (Action::PlayPause, "play-pause", "Play or pause live updates"),
    (Action::ToggleExpert, "toggle-expert", "Switch this view between Guided and Expert"),
];

/// One key press: a key name ("k", "enter", "[", "f5") and its modifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub key: String,
}

impl Key {
    pub fn plain(key: &str) -> Key {
        Key { ctrl: false, alt: false, shift: false, key: key.to_lowercase() }
    }

    /// "ctrl-k", "alt-shift-x", "?", "space".
    pub fn parse(text: &str) -> Result<Key, KeymapError> {
        let mut k = Key::plain("");
        let mut rest = text.trim();
        loop {
            let lower = rest.to_lowercase();
            if let Some(r) = lower.strip_prefix("ctrl-").filter(|r| !r.is_empty()) {
                k.ctrl = true;
                rest = &rest[rest.len() - r.len()..];
            } else if let Some(r) = lower.strip_prefix("alt-").filter(|r| !r.is_empty()) {
                k.alt = true;
                rest = &rest[rest.len() - r.len()..];
            } else if let Some(r) = lower.strip_prefix("shift-").filter(|r| !r.is_empty()) {
                k.shift = true;
                rest = &rest[rest.len() - r.len()..];
            } else {
                break;
            }
        }
        // "ctrl-" (a modifier with no key) is a mistake; "ctrl--" is Ctrl and minus.
        if rest.is_empty()
            || rest.contains(char::is_whitespace)
            || (rest.len() > 1 && rest.ends_with('-') && !rest.ends_with("--"))
        {
            return Err(KeymapError::BadKey(text.to_string()));
        }
        k.key = match rest.to_lowercase().as_str() {
            "esc" => "escape".into(),
            "return" => "enter".into(),
            "arrowdown" => "down".into(),
            "arrowup" => "up".into(),
            other => other.to_string(),
        };
        Ok(k)
    }

    fn has_modifier(&self) -> bool {
        self.ctrl || self.alt
    }
}

impl fmt::Display for Key {
    /// How a key is shown to people: "Ctrl K", "g", "Esc", "↓".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ctrl {
            f.write_str("Ctrl ")?;
        }
        if self.alt {
            f.write_str("Alt ")?;
        }
        if self.shift {
            f.write_str("Shift ")?;
        }
        let shown = match self.key.as_str() {
            "escape" => "Esc".to_string(),
            "enter" => "Enter".into(),
            "down" => "↓".into(),
            "up" => "↑".into(),
            "space" => "Space".into(),
            k if self.ctrl && k.chars().count() == 1 => k.to_uppercase(),
            k => k.to_string(),
        };
        f.write_str(&shown)
    }
}

/// A binding's keys: one key, or a chord of several pressed one after another.
pub type Chord = Vec<Key>;

pub fn parse_chord(text: &str) -> Result<Chord, KeymapError> {
    let keys: Result<Chord, _> = text.split_whitespace().map(Key::parse).collect();
    let keys = keys?;
    if keys.is_empty() || keys.len() > 3 {
        return Err(KeymapError::BadKey(text.to_string()));
    }
    Ok(keys)
}

pub fn show_chord(c: &[Key]) -> String {
    c.iter().map(Key::to_string).collect::<Vec<_>>().join(" then ")
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeymapError {
    #[error("'{0}' is not a key Vigil understands (try \"ctrl-k\", \"j\" or \"g h\")")]
    BadKey(String),
    #[error("'{0}' is not an action (see the shortcut sheet, ?, for the names)")]
    BadAction(String),
    #[error("{keys} is bound to both {a} and {b}")]
    Clash { keys: String, a: String, b: String },
    #[error("{prefix} is bound to {a}, so the chord {chord} ({b}) can never be typed")]
    Prefix { prefix: String, a: String, chord: String, b: String },
    #[error("keys.toml: {0}")]
    Toml(String),
}

/// The defaults from docs/RUST_REWRITE.md 5.5.
pub fn defaults() -> Vec<(Chord, Action)> {
    let mut out: Vec<(&str, Action)> = vec![
        ("ctrl-k", Action::Palette),
        ("j", Action::Down),
        ("down", Action::Down),
        ("k", Action::Up),
        ("up", Action::Up),
        ("enter", Action::Open),
        ("escape", Action::Back),
        ("[", Action::PrevTab),
        ("]", Action::NextTab),
        ("ctrl-[", Action::HistoryBack),
        ("ctrl-]", Action::HistoryForward),
        ("/", Action::Filter),
        ("?", Action::Shortcuts),
        (",", Action::Settings),
        ("c", Action::Copy),
        ("r", Action::Run),
        ("e", Action::SetAside),
        ("a", Action::AddToCase),
        ("p", Action::Pivot),
        ("t", Action::TimeMachine),
        ("space", Action::PlayPause),
        ("x", Action::ToggleExpert),
    ];
    let numbers: Vec<String> = (1..=AREAS.len()).map(|n| n.to_string()).collect();
    let chords: Vec<String> = AREAS.iter().map(|a| format!("g {}", a.g_key)).collect();
    for (i, n) in numbers.iter().enumerate() {
        out.push((n.as_str(), Action::GoArea(i)));
    }
    for (i, c) in chords.iter().enumerate() {
        // "g h" plays the arrival on the way Home, like clicking the mark.
        out.push((c.as_str(), if i == 0 { Action::Arrival } else { Action::GoArea(i) }));
    }
    out.into_iter().map(|(k, a)| (parse_chord(k).expect("default keys parse"), a)).collect()
}

#[derive(Debug, Deserialize, Default)]
struct KeysFile {
    #[serde(default)]
    bindings: BTreeMap<String, String>,
}

/// What a key press did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Action(Action),
    /// The first key(s) of a chord: wait for the next one (show "g …" in the status).
    Pending(Chord),
    /// Not bound here: let the focused widget have it (typing, for a text field).
    Unbound,
}

#[derive(Debug, Clone)]
pub struct Keymap {
    bindings: Vec<(Chord, Action)>,
    pending: Chord,
}

impl Default for Keymap {
    fn default() -> Self {
        Keymap::new(defaults()).expect("the defaults do not clash")
    }
}

impl Keymap {
    pub fn new(bindings: Vec<(Chord, Action)>) -> Result<Keymap, KeymapError> {
        check(&bindings)?;
        Ok(Keymap { bindings, pending: vec![] })
    }

    /// The defaults with the user's keys.toml applied on top.
    pub fn with_overrides(toml_text: &str) -> Result<Keymap, KeymapError> {
        let file: KeysFile = toml::from_str(toml_text).map_err(|e| KeymapError::Toml(e.message().to_string()))?;
        let mut bindings = defaults();
        for (keys, action) in file.bindings {
            let chord = parse_chord(&keys)?;
            bindings.retain(|(c, _)| *c != chord);
            if action != "none" {
                let a = Action::parse(&action).ok_or(KeymapError::BadAction(action.clone()))?;
                bindings.push((chord, a));
            }
        }
        Keymap::new(bindings)
    }

    pub fn bindings(&self) -> &[(Chord, Action)] {
        &self.bindings
    }

    /// Every chord bound to `action`, shortest first (for tooltips: "Settings (,)").
    pub fn keys_for(&self, action: Action) -> Vec<&Chord> {
        let mut v: Vec<&Chord> = self.bindings.iter().filter(|(_, a)| *a == action).map(|(c, _)| c).collect();
        v.sort_by_key(|c| c.len());
        v
    }

    pub fn pending(&self) -> &[Key] {
        &self.pending
    }

    pub fn cancel(&mut self) {
        self.pending.clear();
    }

    /// One key press. `typing` is true while a text field has focus.
    pub fn feed(&mut self, key: Key, typing: bool) -> Outcome {
        let live = |c: &Chord| !typing || c.iter().all(|k| k.has_modifier() || k.key == "escape");
        let mut seq = std::mem::take(&mut self.pending);
        seq.push(key.clone());
        if let Some((_, a)) = self.bindings.iter().find(|(c, _)| *c == seq && live(c)) {
            return Outcome::Action(*a);
        }
        if self.bindings.iter().any(|(c, _)| c.len() > seq.len() && c.starts_with(&seq) && live(c)) {
            self.pending = seq.clone();
            return Outcome::Pending(seq);
        }
        // A broken chord: start over with this key alone ("g" then "1" still jumps to 1).
        if seq.len() > 1 {
            return self.feed(key, typing);
        }
        Outcome::Unbound
    }
}

fn check(bindings: &[(Chord, Action)]) -> Result<(), KeymapError> {
    for (i, (c1, a1)) in bindings.iter().enumerate() {
        for (c2, a2) in &bindings[i + 1..] {
            if c1 == c2 && a1 != a2 {
                return Err(KeymapError::Clash { keys: show_chord(c1), a: a1.name(), b: a2.name() });
            }
            let (short, s_a, long, l_a) = if c1.len() < c2.len() { (c1, a1, c2, a2) } else { (c2, a2, c1, a1) };
            if short.len() < long.len() && long.starts_with(short) {
                return Err(KeymapError::Prefix {
                    prefix: show_chord(short),
                    a: s_a.name(),
                    chord: show_chord(long),
                    b: l_a.name(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(m: &mut Keymap, k: &str) -> Outcome {
        m.feed(Key::parse(k).unwrap(), false)
    }

    #[test]
    fn every_documented_action_has_a_key() {
        let m = Keymap::default();
        for (a, _, _) in ACTION_NAMES {
            assert!(!m.keys_for(*a).is_empty(), "{a:?} has no key");
        }
        for i in 0..AREAS.len() {
            assert!(!m.keys_for(Action::GoArea(i)).is_empty());
        }
    }

    #[test]
    fn chords_numbers_and_typing() {
        let mut m = Keymap::default();
        assert_eq!(press(&mut m, "ctrl-k"), Outcome::Action(Action::Palette));
        assert!(matches!(press(&mut m, "g"), Outcome::Pending(_)));
        assert_eq!(press(&mut m, "n"), Outcome::Action(Action::GoArea(1)));
        assert!(matches!(press(&mut m, "g"), Outcome::Pending(_)));
        assert_eq!(press(&mut m, "h"), Outcome::Action(Action::Arrival));
        // A broken chord falls back to the second key on its own.
        press(&mut m, "g");
        assert_eq!(press(&mut m, "3"), Outcome::Action(Action::GoArea(2)));
        assert_eq!(press(&mut m, "9"), Outcome::Action(Action::GoArea(8)));
        // Typing in a text field: letters type, Ctrl K and Esc still work.
        assert_eq!(m.feed(Key::plain("j"), true), Outcome::Unbound);
        assert_eq!(m.feed(Key::plain("g"), true), Outcome::Unbound);
        assert_eq!(m.feed(Key::parse("ctrl-k").unwrap(), true), Outcome::Action(Action::Palette));
        assert_eq!(m.feed(Key::plain("escape"), true), Outcome::Action(Action::Back));
        assert_eq!(press(&mut m, "ctrl-["), Outcome::Action(Action::HistoryBack));
    }

    #[test]
    fn rebinding_from_toml() {
        let m = Keymap::with_overrides("[bindings]\n\"ctrl-p\" = \"palette\"\n\"x\" = \"none\"\n").unwrap();
        assert_eq!(m.keys_for(Action::Palette).len(), 2);
        assert!(m.keys_for(Action::ToggleExpert).is_empty());
        let err = Keymap::with_overrides("[bindings]\n\"g\" = \"settings\"\n").unwrap_err();
        assert!(matches!(err, KeymapError::Prefix { .. }), "{err}");
        assert!(matches!(Keymap::with_overrides("[bindings]\n\"q\" = \"fly\"\n"), Err(KeymapError::BadAction(_))));
        assert!(matches!(Keymap::with_overrides("[bindings]\n\"ctrl-\" = \"palette\"\n"), Err(KeymapError::BadKey(_))));
        // Moving a default to a new key frees the old one.
        let m = Keymap::with_overrides("[bindings]\n\"c\" = \"none\"\n\"y\" = \"copy\"\n").unwrap();
        assert_eq!(show_chord(m.keys_for(Action::Copy)[0]), "y");
    }

    #[test]
    fn names_round_trip_and_display() {
        for (_, a) in defaults() {
            assert_eq!(Action::parse(&a.name()), Some(a));
        }
        assert_eq!(Key::parse("ctrl-k").unwrap().to_string(), "Ctrl K");
        assert_eq!(show_chord(&parse_chord("g h").unwrap()), "g then h");
        assert_eq!(Key::parse("Esc").unwrap().key, "escape");
    }
}
