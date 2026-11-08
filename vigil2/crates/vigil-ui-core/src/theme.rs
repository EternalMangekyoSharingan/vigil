//! Vigil's look: the token set from Vigil 1's `vigil/ui/static/style.css`, as data.
//!
//! Dark plum base, warm orange for action and selection, the wallpaper's teal to ice
//! cyan for live network activity, red and amber only for severity. Colour only for
//! meaning. Three themes from day one (dark, light, high contrast); the tests hold every
//! one to WCAG contrast ratios. A theme file (`~/.config/vigil/theme.toml`) can
//! override any token, and the app reloads it when it changes, so trying a colour does
//! not need a rebuild.

use serde::Deserialize;
use std::collections::BTreeMap;

/// 0xRRGGBBAA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgba(pub u32);

impl Rgba {
    pub const fn rgb(hex: u32) -> Rgba {
        Rgba((hex << 8) | 0xff)
    }
    pub const fn with_alpha(self, a: u8) -> Rgba {
        Rgba((self.0 & 0xffff_ff00) | a as u32)
    }
    pub fn channels(self) -> (f32, f32, f32, f32) {
        let c = |s: u32| ((self.0 >> s) & 0xff) as f32 / 255.0;
        (c(24), c(16), c(8), c(0))
    }
    /// "#rrggbb" or "#rrggbbaa".
    pub fn parse(s: &str) -> Option<Rgba> {
        let h = s.strip_prefix('#')?;
        let v = u32::from_str_radix(h, 16).ok()?;
        match h.len() {
            6 => Some(Rgba::rgb(v)),
            8 => Some(Rgba(v)),
            _ => None,
        }
    }
    /// This colour drawn over an opaque `bg`.
    pub fn over(self, bg: Rgba) -> Rgba {
        let (r, g, b, a) = self.channels();
        let (br, bgc, bb, _) = bg.channels();
        let m = |f: f32, b: f32| ((f * a + b * (1.0 - a)) * 255.0).round() as u32;
        Rgba((m(r, br) << 24) | (m(g, bgc) << 16) | (m(b, bb) << 8) | 0xff)
    }
}

fn luminance(c: Rgba) -> f32 {
    let (r, g, b, _) = c.channels();
    let f = |c: f32| if c <= 0.03928 { c / 12.92 } else { ((c + 0.055) / 1.055).powf(2.4) };
    0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
}

/// WCAG 2 contrast ratio of `fg` drawn on `bg` (1 to 21).
pub fn contrast(fg: Rgba, bg: Rgba) -> f32 {
    let (a, b) = (luminance(fg.over(bg)), luminance(bg));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    pub name: &'static str,
    /// Window, rail, card, raised, hover.
    pub bg: [Rgba; 5],
    /// Hairlines: subtle, normal, strong.
    pub line: [Rgba; 3],
    /// Primary, secondary, tertiary text.
    pub text: [Rgba; 3],
    /// Action and selection.
    pub accent: Rgba,
    pub accent_hi: Rgba,
    pub accent_soft: Rgba,
    /// Live network activity: teal to ice.
    pub live: Rgba,
    pub live_hi: Rgba,
    pub danger: Rgba,
    pub danger_text: Rgba,
    pub warn: Rgba,
    pub ok: Rgba,
    pub radius: f32,
    pub radius_sm: f32,
    pub rail_width: f32,
    pub pad: f32,
    pub control_height: f32,
    /// Font families in order of preference.
    pub ui_fonts: &'static [&'static str],
    pub mono_fonts: &'static [&'static str],
}

const UI_FONTS: &[&str] = &["SF Pro Text", "Inter", "Inter Variable", "Cantarell", "Noto Sans", "DejaVu Sans"];
const MONO_FONTS: &[&str] = &["JetBrains Mono", "SF Mono", "Fira Mono", "DejaVu Sans Mono"];

pub fn dark() -> Theme {
    Theme {
        name: "dark",
        bg: [Rgba::rgb(0x110e15), Rgba::rgb(0x16121b), Rgba::rgb(0x1c1722), Rgba::rgb(0x241e2c), Rgba::rgb(0x2d2637)],
        line: [Rgba(0xffffff12), Rgba(0xffffff1f), Rgba(0xffffff33)],
        // Tertiary text is #8a8299, a step lighter than Vigil 1's #716a82, which was
        // below WCAG AA (3.7:1) on the window background.
        text: [Rgba::rgb(0xece7f2), Rgba::rgb(0xaaa1b8), Rgba::rgb(0x8a8299)],
        accent: Rgba::rgb(0xff9f43),
        accent_hi: Rgba::rgb(0xffb76b),
        accent_soft: Rgba(0xff9f431f),
        live: Rgba::rgb(0x5dbdb9),
        live_hi: Rgba::rgb(0x62f3ff),
        danger: Rgba::rgb(0xff5d73),
        danger_text: Rgba::rgb(0xff8b9b),
        warn: Rgba::rgb(0xf5c451),
        ok: Rgba::rgb(0x5dd39e),
        radius: 10.0,
        radius_sm: 7.0,
        rail_width: 68.0,
        pad: 24.0,
        control_height: 32.0,
        ui_fonts: UI_FONTS,
        mono_fonts: MONO_FONTS,
    }
}

pub fn light() -> Theme {
    Theme {
        name: "light",
        bg: [Rgba::rgb(0xf7f5fa), Rgba::rgb(0xf1edf5), Rgba::rgb(0xffffff), Rgba::rgb(0xe8e3ef), Rgba::rgb(0xddd6e6)],
        line: [Rgba(0x1d18241a), Rgba(0x1d182429), Rgba(0x1d182447)],
        text: [Rgba::rgb(0x1d1824), Rgba::rgb(0x554d61), Rgba::rgb(0x6f6780)],
        accent: Rgba::rgb(0xb4560a),
        accent_hi: Rgba::rgb(0xd4680f),
        accent_soft: Rgba(0xb4560a1f),
        live: Rgba::rgb(0x00756b),
        live_hi: Rgba::rgb(0x00838f),
        danger: Rgba::rgb(0xc4243f),
        danger_text: Rgba::rgb(0xb01f38),
        warn: Rgba::rgb(0x8a5d00),
        ok: Rgba::rgb(0x1b7a50),
        ..dark()
    }
}

pub fn high_contrast() -> Theme {
    Theme {
        name: "high-contrast",
        bg: [Rgba::rgb(0x000000), Rgba::rgb(0x000000), Rgba::rgb(0x0b0b0b), Rgba::rgb(0x161616), Rgba::rgb(0x222222)],
        line: [Rgba(0xffffff66), Rgba(0xffffff99), Rgba(0xffffffcc)],
        text: [Rgba::rgb(0xffffff), Rgba::rgb(0xe6e6e6), Rgba::rgb(0xcccccc)],
        accent: Rgba::rgb(0xffb15c),
        accent_hi: Rgba::rgb(0xffc98a),
        accent_soft: Rgba(0xffb15c33),
        live: Rgba::rgb(0x7ff7ff),
        live_hi: Rgba::rgb(0xb8fbff),
        danger: Rgba::rgb(0xff8b9b),
        danger_text: Rgba::rgb(0xffb3bf),
        warn: Rgba::rgb(0xffd666),
        ok: Rgba::rgb(0x7ee8b5),
        ..dark()
    }
}

pub fn by_name(name: &str) -> Theme {
    match name {
        "light" => light(),
        "high-contrast" => high_contrast(),
        _ => dark(),
    }
}

#[derive(Debug, Deserialize, Default)]
struct ThemeFile {
    base: Option<String>,
    #[serde(default)]
    colors: BTreeMap<String, String>,
    radius: Option<f32>,
}

/// A theme file on top of a base theme. Unknown or malformed tokens are reported, not
/// guessed: the result lists what was ignored and why.
pub fn with_overrides(base: Theme, toml_text: &str) -> (Theme, Vec<String>) {
    let mut problems = vec![];
    let file: ThemeFile = match toml::from_str(toml_text) {
        Ok(f) => f,
        Err(e) => return (base, vec![format!("theme file: {}", e.message())]),
    };
    let mut t = file.base.as_deref().map_or(base, by_name);
    if let Some(r) = file.radius {
        t.radius = r.clamp(0.0, 24.0);
    }
    for (k, v) in file.colors {
        let Some(c) = Rgba::parse(&v) else {
            problems.push(format!("{k}: '{v}' is not #rrggbb or #rrggbbaa"));
            continue;
        };
        let slot = match k.as_str() {
            "bg-0" => &mut t.bg[0],
            "bg-1" => &mut t.bg[1],
            "bg-2" => &mut t.bg[2],
            "bg-3" => &mut t.bg[3],
            "bg-4" => &mut t.bg[4],
            "text" => &mut t.text[0],
            "text-2" => &mut t.text[1],
            "text-3" => &mut t.text[2],
            "accent" => &mut t.accent,
            "live" => &mut t.live,
            "live-hi" => &mut t.live_hi,
            "danger" => &mut t.danger,
            "warn" => &mut t.warn,
            "ok" => &mut t.ok,
            _ => {
                problems.push(format!("{k}: not a theme token"));
                continue;
            }
        };
        *slot = c;
    }
    (t, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_theme_meets_wcag_contrast() {
        for t in [dark(), light(), high_contrast()] {
            let need = if t.name == "high-contrast" { 7.0 } else { 4.5 };
            for (i, bg) in t.bg.iter().enumerate() {
                for (j, fg) in t.text[..2].iter().enumerate() {
                    let c = contrast(*fg, *bg);
                    assert!(c >= need, "{}: text {j} on bg {i} is {c:.2}", t.name);
                }
                // Tertiary text is for hints on cards (bg 0-2); 3:1 is the floor elsewhere.
                let c = contrast(t.text[2], *bg);
                assert!(c >= if i <= 2 { 4.5 } else { 3.0 }, "{}: text 3 on bg {i} is {c:.2}", t.name);
                // Colours that carry meaning must stand out as UI (WCAG 1.4.11: 3:1).
                for (name, c) in
                    [("accent", t.accent), ("live", t.live), ("danger", t.danger), ("warn", t.warn), ("ok", t.ok)]
                {
                    assert!(contrast(c, *bg) >= 3.0, "{}: {name} on bg {i} is {:.2}", t.name, contrast(c, *bg));
                }
            }
        }
    }

    #[test]
    fn identity_tokens_match_vigil_1() {
        let t = dark();
        assert_eq!(t.bg[0], Rgba::rgb(0x110e15));
        assert_eq!(t.bg[4], Rgba::rgb(0x2d2637));
        assert_eq!(t.accent, Rgba::rgb(0xff9f43));
        assert_eq!((t.live, t.live_hi), (Rgba::rgb(0x5dbdb9), Rgba::rgb(0x62f3ff)));
        assert_eq!(t.radius, 10.0);
    }

    #[test]
    fn theme_file_overrides() {
        let (t, problems) =
            with_overrides(dark(), "radius = 8\n[colors]\naccent = \"#ff8800\"\nnope = \"#000000\"\ntext = \"blue\"\n");
        assert_eq!(t.accent, Rgba::rgb(0xff8800));
        assert_eq!(t.radius, 8.0);
        assert_eq!(problems.len(), 2);
        let (t, _) = with_overrides(dark(), "base = \"light\"\n");
        assert_eq!(t.name, "light");
        let (_, p) = with_overrides(dark(), "this is not toml");
        assert_eq!(p.len(), 1);
    }
}
