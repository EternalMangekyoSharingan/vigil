//! Program icons, the way the desktop shows them: from `.desktop` files (system, user,
//! Flatpak, Snap) and the icon theme. Built once on a background thread; lookups are by
//! the running program's executable path.
//!
//! Matching is by the executable's file name against each launcher's `Exec=`, its
//! `StartupWMClass=` and the launcher's own file name ("brave" finds
//! brave-browser.desktop). Nothing is run; only files are read.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Default)]
pub struct AppIcons {
    /// Lower-case key -> icon file.
    by_key: HashMap<String, Arc<Path>>,
    /// Answers already worked out, misses included (lookups run for every visible row).
    memo: std::sync::Mutex<HashMap<String, Option<Arc<Path>>>>,
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default()
}

fn app_dirs() -> Vec<PathBuf> {
    let h = home();
    let mut v = vec![
        PathBuf::from("/usr/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        PathBuf::from("/var/lib/flatpak/exports/share/applications"),
        PathBuf::from("/var/lib/snapd/desktop/applications"),
        h.join(".local/share/applications"),
        h.join(".local/share/flatpak/exports/share/applications"),
    ];
    if let Ok(dirs) = std::env::var("XDG_DATA_DIRS") {
        v.extend(dirs.split(':').filter(|d| !d.is_empty()).map(|d| PathBuf::from(d).join("applications")));
    }
    v.dedup();
    v
}

fn icon_bases() -> Vec<PathBuf> {
    let h = home();
    vec![
        h.join(".local/share/icons"),
        h.join(".icons"),
        PathBuf::from("/usr/share/icons"),
        PathBuf::from("/usr/local/share/icons"),
        PathBuf::from("/var/lib/flatpak/exports/share/icons"),
        h.join(".local/share/flatpak/exports/share/icons"),
    ]
}

/// The icon theme in use: KDE's kdeglobals, then GTK's settings, then nothing.
fn current_theme() -> Option<String> {
    let h = home();
    let kde = std::fs::read_to_string(h.join(".config/kdeglobals")).ok().and_then(|t| {
        let mut in_icons = false;
        for l in t.lines() {
            let l = l.trim();
            if l.starts_with('[') {
                in_icons = l == "[Icons]";
            } else if in_icons {
                if let Some(v) = l.strip_prefix("Theme=") {
                    return Some(v.to_string());
                }
            }
        }
        None
    });
    kde.or_else(|| {
        std::fs::read_to_string(h.join(".config/gtk-3.0/settings.ini"))
            .ok()?
            .lines()
            .find_map(|l| l.trim().strip_prefix("gtk-icon-theme-name=").map(|v| v.trim().to_string()))
    })
}

fn resolve_icon(name: &str, themes: &[String]) -> Option<Arc<Path>> {
    let p = Path::new(name);
    if p.is_absolute() {
        return p.exists().then(|| Arc::from(p));
    }
    let sizes = ["scalable", "256x256", "128x128", "96x96", "64x64", "48x48", "32x32", "apps/64", "apps/48", "apps/32"];
    for base in icon_bases() {
        for theme in themes {
            for size in sizes {
                let dir = if size.starts_with("apps/") {
                    base.join(theme).join(size)
                } else {
                    base.join(theme).join(size).join("apps")
                };
                for ext in ["svg", "png"] {
                    let f = dir.join(format!("{name}.{ext}"));
                    if f.exists() {
                        return Some(Arc::from(f.as_path()));
                    }
                }
            }
        }
    }
    for ext in ["svg", "png"] {
        let f = PathBuf::from(format!("/usr/share/pixmaps/{name}.{ext}"));
        if f.exists() {
            return Some(Arc::from(f.as_path()));
        }
    }
    None
}

/// The program a launcher's Exec= line starts, ignoring `env VAR=x` and `flatpak run`.
fn exec_program(exec: &str) -> Option<String> {
    let mut words = exec.split_whitespace().filter(|w| !w.contains('=') || w.starts_with('/'));
    let mut first = words.next()?;
    if first.ends_with("/env") || first == "env" {
        first = words.next()?;
    }
    if first.ends_with("flatpak") {
        return words.find(|w| !w.starts_with('-') && *w != "run").map(|w| w.to_lowercase());
    }
    Some(first.rsplit('/').next()?.trim_matches('"').to_lowercase())
}

impl AppIcons {
    pub fn load() -> AppIcons {
        let mut themes: Vec<String> = current_theme().into_iter().collect();
        for t in ["breeze", "breeze-dark", "Adwaita", "hicolor"] {
            if !themes.iter().any(|x| x == t) {
                themes.push(t.into());
            }
        }
        let mut by_key = HashMap::new();
        for dir in app_dirs() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for e in entries.flatten() {
                let path = e.path();
                if path.extension().and_then(|x| x.to_str()) != Some("desktop") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else { continue };
                let (mut icon, mut exec, mut class) = (None, None, None);
                let mut in_entry = false;
                for l in text.lines() {
                    let l = l.trim();
                    if l.starts_with('[') {
                        in_entry = l == "[Desktop Entry]";
                        continue;
                    }
                    if !in_entry {
                        continue;
                    }
                    if let Some(v) = l.strip_prefix("Icon=") {
                        icon = Some(v.to_string());
                    } else if let Some(v) = l.strip_prefix("Exec=") {
                        exec = exec_program(v);
                    } else if let Some(v) = l.strip_prefix("StartupWMClass=") {
                        class = Some(v.to_lowercase());
                    }
                }
                let Some(icon) = icon.and_then(|i| resolve_icon(&i, &themes)) else { continue };
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                let mut keys = vec![stem.clone(), stem.rsplit('.').next().unwrap_or("").to_string()];
                keys.extend(exec.clone());
                keys.extend(class);
                for k in keys.into_iter().filter(|k| k.len() > 1) {
                    by_key.entry(k).or_insert_with(|| icon.clone());
                }
            }
        }
        AppIcons { by_key, memo: Default::default() }
    }

    /// The icon for a program, by its executable path (or its program key).
    pub fn for_exe(&self, exe: &str) -> Option<Arc<Path>> {
        let mut memo = self.memo.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = memo.get(exe) {
            return hit.clone();
        }
        let found = self.lookup(exe);
        memo.insert(exe.to_string(), found.clone());
        found
    }

    fn lookup(&self, exe: &str) -> Option<Arc<Path>> {
        let first = exe.split(' ').next().unwrap_or(exe);
        let base = first.rsplit('/').next().unwrap_or(first).trim_end_matches(" (deleted)").to_lowercase();
        if base.is_empty() {
            return None;
        }
        if let Some(p) = self.by_key.get(&base) {
            return Some(p.clone());
        }
        // "brave" -> "brave-browser", "code" -> "code-oss": a launcher named after the program.
        let mut best: Option<(&String, &Arc<Path>)> = None;
        for (k, p) in &self.by_key {
            if k.starts_with(&base)
                && k[base.len()..].starts_with(['-', '_', '.'])
                && best.is_none_or(|(b, _)| k.len() < b.len())
            {
                best = Some((k, p));
            }
        }
        best.map(|(_, p)| p.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::exec_program;

    #[test]
    fn exec_lines() {
        assert_eq!(exec_program("/usr/bin/brave-browser-stable %U").as_deref(), Some("brave-browser-stable"));
        assert_eq!(exec_program("env BAMF=1 /opt/app/bin/app --x").as_deref(), Some("app"));
        assert_eq!(
            exec_program("/usr/bin/flatpak run --branch=stable --command=signal org.signal.Signal").as_deref(),
            Some("org.signal.signal")
        );
    }
}
