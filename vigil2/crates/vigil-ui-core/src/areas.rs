//! The areas on the rail, in rail order (keys 1-9), with the question each answers.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Area {
    Home,
    Network,
    Processes,
    Autostart,
    Files,
    Software,
    Guard,
    Canaries,
    Cases,
}

pub struct AreaInfo {
    pub area: Area,
    pub name: &'static str,
    /// Machine name, used in key bindings ("go-network") and saved layouts.
    pub id: &'static str,
    /// The letter after `g` that jumps here.
    pub g_key: char,
    pub question: &'static str,
    pub tabs: &'static [&'static str],
    /// Vigil 1's tool this area grew from, if any.
    pub was: Option<&'static str>,
}

pub const AREAS: [AreaInfo; 9] = [
    AreaInfo {
        area: Area::Home,
        name: "Home",
        id: "home",
        g_key: 'h',
        question: "How is this PC doing, and what needs a look?",
        tabs: &["Overview", "Since you last looked", "Storylines"],
        was: Some("Home"),
    },
    AreaInfo {
        area: Area::Network,
        name: "Network",
        id: "network",
        g_key: 'n',
        question: "Who is this PC talking to, and which program?",
        tabs: &["Map", "Connections", "DNS", "Time machine", "LAN"],
        was: Some("Net"),
    },
    AreaInfo {
        area: Area::Processes,
        name: "Processes",
        id: "processes",
        g_key: 'p',
        question: "What is running, where did it come from, and should it be?",
        tabs: &["Tree", "Table", "Secrets"],
        was: Some("Tasks"),
    },
    AreaInfo {
        area: Area::Autostart,
        name: "Autostart",
        id: "autostart",
        g_key: 'a',
        question: "What starts by itself, and what changed?",
        tabs: &["Changes", "Everything", "Baseline"],
        was: Some("Persist"),
    },
    AreaInfo {
        area: Area::Files,
        name: "Files",
        id: "files",
        g_key: 'f',
        question: "Is this file or archive safe to open?",
        tabs: &["Inspect", "Downloads", "Quarantine"],
        was: Some("Files"),
    },
    AreaInfo {
        area: Area::Software,
        name: "Software",
        id: "software",
        g_key: 's',
        question: "Is this software safe to install, and is what you have up to date?",
        tabs: &["Review", "Installed", "Flatpak", "Extensions", "CVEs"],
        was: Some("Pkg"),
    },
    AreaInfo {
        area: Area::Guard,
        name: "Guard",
        id: "guard",
        g_key: 'd',
        question: "How well is this PC defended?",
        tabs: &["Posture", "Listening", "Hardening"],
        was: None,
    },
    AreaInfo {
        area: Area::Canaries,
        name: "Canaries",
        id: "canaries",
        g_key: 'y',
        question: "Has anything touched the decoys?",
        tabs: &["Decoys", "Alerts"],
        was: None,
    },
    AreaInfo {
        area: Area::Cases,
        name: "Cases",
        id: "cases",
        g_key: 'c',
        question: "What happened, across all of the above?",
        tabs: &["Timeline", "Cases", "Analyst"],
        was: Some("Cases"),
    },
];

pub fn info(area: Area) -> &'static AreaInfo {
    AREAS.iter().find(|a| a.area == area).expect("every area is listed")
}

pub fn by_number(n: usize) -> Option<Area> {
    AREAS.get(n.checked_sub(1)?).map(|a| a.area)
}

pub fn by_id(id: &str) -> Option<Area> {
    AREAS.iter().find(|a| a.id == id).map(|a| a.area)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g_keys_are_unique_and_areas_fit_on_number_keys() {
        let mut keys: Vec<char> = AREAS.iter().map(|a| a.g_key).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), AREAS.len());
        assert!(AREAS.len() <= 9);
        assert_eq!(by_number(1), Some(Area::Home));
        assert_eq!(by_number(10), None);
        assert_eq!(by_id("cases"), Some(Area::Cases));
    }
}
