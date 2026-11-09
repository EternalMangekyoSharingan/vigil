//! The app's own preferences (`~/.config/vigil/ui.toml`): look, motion, Guided or
//! Expert per area, favourites, whether onboarding is done.
//!
//! Security settings (Run mode, network features, retention) are not here: they live in
//! the daemon, behind polkit (`org.vigil.manage`), so a program running as the user
//! cannot quietly switch them on.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::motion::MotionPref;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Density {
    #[default]
    Comfortable,
    Compact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum View {
    /// Plain-language cards, one recommended next step.
    #[default]
    Guided,
    /// Dense tables, raw values, a query bar.
    Expert,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSettings {
    pub theme: String,
    pub motion: MotionPref,
    pub density: Density,
    /// Guided or Expert, per area id ("network", "processes" ...).
    pub views: BTreeMap<String, View>,
    pub favourites: Vec<String>,
    pub onboarded: bool,
    /// The network map's background: "grid" (hexagons and shapes), "night" (stars) or
    /// "plain". All three are still: nothing on the map moves.
    pub map_background: String,
}

impl Default for UiSettings {
    fn default() -> Self {
        UiSettings {
            theme: "dark".into(),
            motion: MotionPref::System,
            density: Density::Comfortable,
            views: BTreeMap::new(),
            favourites: vec![],
            onboarded: false,
            map_background: "grid".into(),
        }
    }
}

impl UiSettings {
    pub fn view(&self, area_id: &str) -> View {
        self.views.get(area_id).copied().unwrap_or_default()
    }

    pub fn toggle_view(&mut self, area_id: &str) -> View {
        let v = match self.view(area_id) {
            View::Guided => View::Expert,
            View::Expert => View::Guided,
        };
        self.views.insert(area_id.to_string(), v);
        v
    }

    /// Read the file; a missing or broken file gives the defaults (and says why).
    pub fn load(path: &Path) -> (UiSettings, Option<String>) {
        match std::fs::read_to_string(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (UiSettings::default(), None),
            Err(e) => (UiSettings::default(), Some(format!("{}: {e}", path.display()))),
            Ok(text) => match toml::from_str(&text) {
                Ok(s) => (s, None),
                Err(e) => (UiSettings::default(), Some(format!("{}: {}", path.display(), e.message()))),
            },
        }
    }

    /// Write atomically, readable only by the user.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        if let Some(dir) = path.parent() {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        let tmp = path.with_extension("toml.tmp");
        let text = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    }
}

/// `$XDG_CONFIG_HOME/vigil`, else `~/.config/vigil`.
pub fn config_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|p| p.join("vigil"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn round_trip_private_and_forgiving() {
        let dir = std::env::temp_dir().join(format!("vigil-ui-test-{}", std::process::id()));
        let p = dir.join("ui.toml");
        let mut s = UiSettings::default();
        assert_eq!(s.toggle_view("network"), View::Expert);
        s.motion = MotionPref::Reduced;
        s.save(&p).unwrap();
        assert_eq!(UiSettings::load(&p), (s.clone(), None));
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&p, "motion = 12").unwrap();
        let (d, why) = UiSettings::load(&p);
        assert_eq!(d, UiSettings::default());
        assert!(why.is_some());
        assert_eq!(UiSettings::load(&dir.join("missing.toml")), (UiSettings::default(), None));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
