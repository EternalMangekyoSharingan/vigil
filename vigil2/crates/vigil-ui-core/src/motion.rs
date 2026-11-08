//! Motion: gorgeous, never in the way (docs/RUST_REWRITE.md 5.3).
//!
//! Pure functions of time, so every animation can be tested frame by frame and a
//! toolkit only has to ask "what does frame t look like?". Rules enforced by the tests:
//! nothing but the arrival lasts longer than [`MAX_TRANSITION_MS`]; reduced motion
//! skips the arrival; any key skips it too (the app jumps to [`ARRIVAL_MS`]).

/// The arrival ("about 700 ms").
pub const ARRIVAL_MS: f32 = 700.0;
/// Every other transition is at most this long.
pub const MAX_TRANSITION_MS: f32 = 300.0;
/// The rail's active marker slides between items.
pub const RAIL_MARKER_MS: f32 = 220.0;
/// Tabs cross-fade with a small slide.
pub const TAB_MS: f32 = 180.0;
pub const TAB_SLIDE_PX: f32 = 6.0;
/// A list row grows into the detail panel's header.
pub const SHARED_ELEMENT_MS: f32 = 240.0;
/// Home's cards rise into place after the arrival, one after another.
pub const CARD_STAGGER_MS: f32 = 30.0;
pub const CARD_RISE_MS: f32 = 220.0;
pub const CARD_RISE_PX: f32 = 12.0;

/// CSS `cubic-bezier(x1, y1, x2, y2)` at progress `t` (0..1).
pub fn cubic_bezier(x1: f32, y1: f32, x2: f32, y2: f32, t: f32) -> f32 {
    if t <= 0.0 {
        return 0.0;
    }
    if t >= 1.0 {
        return 1.0;
    }
    let bez = |a: f32, b: f32, s: f32| 3.0 * a * s * (1.0 - s).powi(2) + 3.0 * b * s * s * (1.0 - s) + s.powi(3);
    // Solve x(s) = t for s by bisection (monotonic for 0 <= x1, x2 <= 1), then return y(s).
    let (mut lo, mut hi) = (0.0f32, 1.0f32);
    for _ in 0..30 {
        let mid = (lo + hi) / 2.0;
        if bez(x1, x2, mid) < t {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    bez(y1, y2, (lo + hi) / 2.0)
}

/// Vigil's standard ease (`--ease` in Vigil 1's style.css).
pub fn ease(t: f32) -> f32 {
    cubic_bezier(0.2, 0.7, 0.2, 1.0, t)
}

/// A damped spring from 0 to 1 (unit mass).
#[derive(Debug, Clone, Copy)]
pub struct Spring {
    pub stiffness: f32,
    pub damping: f32,
}

impl Spring {
    /// The rail marker and the cube faces: lively, settles fast, overshoots a little.
    pub const SNAPPY: Spring = Spring { stiffness: 420.0, damping: 30.0 };

    /// Position at `t` seconds after release.
    pub fn value(self, t: f32) -> f32 {
        if t <= 0.0 {
            return 0.0;
        }
        let w0 = self.stiffness.sqrt();
        let zeta = self.damping / (2.0 * w0);
        if zeta < 1.0 {
            let wd = w0 * (1.0 - zeta * zeta).sqrt();
            1.0 - (-zeta * w0 * t).exp() * ((wd * t).cos() + (zeta * w0 / wd) * (wd * t).sin())
        } else if (zeta - 1.0).abs() < 1e-6 {
            1.0 - (-w0 * t).exp() * (1.0 + w0 * t)
        } else {
            let s = (zeta * zeta - 1.0).sqrt();
            let (r1, r2) = (-w0 * (zeta - s), -w0 * (zeta + s));
            1.0 - (r2 * (r1 * t).exp() - r1 * (r2 * t).exp()) / (r2 - r1)
        }
    }

    /// When it stays within `eps` of 1 for good (seconds), found by sampling.
    pub fn settle_time(self, eps: f32) -> f32 {
        let mut last_out = 0.0;
        let mut t = 0.0;
        while t < 5.0 {
            if (self.value(t) - 1.0).abs() > eps {
                last_out = t;
            }
            t += 0.001;
        }
        last_out
    }
}

/// The motion setting: Vigil's own choice, or the desktop's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MotionPref {
    #[default]
    System,
    Full,
    Reduced,
}

pub fn reduced(pref: MotionPref, desktop_reduced: bool) -> bool {
    match pref {
        MotionPref::Reduced => true,
        MotionPref::Full => false,
        MotionPref::System => desktop_reduced,
    }
}

/// One of the cube's three faces.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Face {
    pub opacity: f32,
    pub dx: f32,
    pub dy: f32,
    pub scale: f32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ring {
    /// Radius as a multiple of the mark's radius.
    pub radius: f32,
    pub opacity: f32,
}

/// What the arrival looks like at one instant.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArrivalFrame {
    pub backdrop: f32,
    /// Top, left, right.
    pub faces: [Face; 3],
    pub core_scale: f32,
    pub core_opacity: f32,
    /// Ice first, then orange.
    pub rings: [Ring; 2],
    pub grid_opacity: f32,
    /// How far from the centre the grid has faded in (0..1 of the window's half-diagonal).
    pub grid_reach: f32,
    /// Letter spacing of the word VIGIL, in em.
    pub word_tracking: f32,
    pub word_blur: f32,
    pub word_opacity: f32,
    pub done: bool,
}

/// Where each face flies in from, in mark units (the mark is 84 px wide at rest).
pub const FACE_FROM: [(f32, f32); 3] = [(0.0, -26.0), (-24.0, 14.0), (24.0, 14.0)];
pub const FACE_STAGGER_MS: f32 = 70.0;
pub const CORE_START_MS: f32 = 300.0;
pub const CORE_PEAK_MS: f32 = 110.0;
pub const CORE_MS: f32 = 240.0;
pub const CORE_PEAK: f32 = 2.2;
pub const RING_START_MS: [f32; 2] = [330.0, 450.0];
pub const RING_MS: f32 = 250.0;
pub const WORD_START_MS: f32 = 250.0;
pub const WORD_MS: f32 = 380.0;

// Every part of the arrival ends inside it (checked when compiling).
const _: () = assert!(RING_START_MS[1] + RING_MS <= ARRIVAL_MS);
const _: () = assert!(CORE_START_MS + CORE_MS <= ARRIVAL_MS);
const _: () = assert!(WORD_START_MS + WORD_MS <= ARRIVAL_MS);

fn progress(t: f32, start: f32, len: f32) -> f32 {
    ((t - start) / len).clamp(0.0, 1.0)
}

/// The arrival at `t` milliseconds. With `reduced` it is already over.
pub fn arrival(t: f32, reduced: bool) -> ArrivalFrame {
    let t = if reduced { ARRIVAL_MS } else { t.max(0.0) };
    let faces = std::array::from_fn(|i| {
        let start = i as f32 * FACE_STAGGER_MS;
        let p = if t >= ARRIVAL_MS { 1.0 } else { Spring::SNAPPY.value((t - start) / 1000.0) };
        let (fx, fy) = FACE_FROM[i];
        Face { opacity: (p * 1.6).clamp(0.0, 1.0), dx: fx * (1.0 - p), dy: fy * (1.0 - p), scale: 0.7 + 0.3 * p }
    });
    // The core ignites with a quick overshoot: 0 -> 2.2 -> 1.
    let ct = t - CORE_START_MS;
    let core_scale = if ct <= 0.0 {
        0.0
    } else if ct < CORE_PEAK_MS {
        CORE_PEAK * ease(ct / CORE_PEAK_MS)
    } else {
        CORE_PEAK + (1.0 - CORE_PEAK) * ease(progress(ct, CORE_PEAK_MS, CORE_MS - CORE_PEAK_MS))
    };
    let rings = std::array::from_fn(|i| {
        let p = progress(t, RING_START_MS[i], RING_MS);
        Ring { radius: 1.0 + 1.6 * ease(p), opacity: if p <= 0.0 || p >= 1.0 { 0.0 } else { 0.9 * (1.0 - p) } }
    });
    let wp = ease(progress(t, WORD_START_MS, WORD_MS));
    ArrivalFrame {
        backdrop: ease(progress(t, 0.0, 250.0)),
        faces,
        core_scale,
        core_opacity: if ct > 0.0 { 1.0 } else { 0.0 },
        rings,
        grid_opacity: 0.18 * ease(progress(t, 80.0, 400.0)),
        grid_reach: ease(progress(t, 80.0, 520.0)),
        word_tracking: 1.6 - 1.0 * wp,
        word_blur: 6.0 * (1.0 - wp),
        word_opacity: wp,
        done: t >= ARRIVAL_MS,
    }
}

/// Home's card `i` after the arrival: (vertical offset in px, opacity).
pub fn card_rise(t_after_arrival: f32, i: usize, reduced: bool) -> (f32, f32) {
    if reduced {
        return (0.0, 1.0);
    }
    let p = ease(progress(t_after_arrival, i as f32 * CARD_STAGGER_MS, CARD_RISE_MS));
    (CARD_RISE_PX * (1.0 - p), p)
}

/// A value easing from `from` to `to` over `len` ms (for counters, markers, tabs).
pub fn tween(from: f32, to: f32, t: f32, len: f32, reduced: bool) -> f32 {
    if reduced || len <= 0.0 {
        return to;
    }
    from + (to - from) * ease((t / len).clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_respect_the_limits() {
        let all = [RAIL_MARKER_MS, TAB_MS, SHARED_ELEMENT_MS, CARD_RISE_MS];
        assert!(all.iter().all(|ms| *ms <= MAX_TRANSITION_MS), "{all:?}");
        assert!(2.0 * FACE_STAGGER_MS + Spring::SNAPPY.settle_time(0.01) * 1000.0 <= ARRIVAL_MS);
        assert!(Spring::SNAPPY.settle_time(0.01) * 1000.0 <= MAX_TRANSITION_MS + 150.0);
    }

    #[test]
    fn arrival_starts_hidden_and_ends_at_rest() {
        let a = arrival(0.0, false);
        assert!(a.faces.iter().all(|f| f.opacity == 0.0));
        assert_eq!(a.core_scale, 0.0);
        assert_eq!(a.word_opacity, 0.0);
        assert!(!a.done);
        let z = arrival(ARRIVAL_MS, false);
        assert!(z.done);
        for f in z.faces {
            assert_eq!((f.opacity, f.dx, f.dy, f.scale), (1.0, 0.0, 0.0, 1.0));
        }
        assert!((z.core_scale - 1.0).abs() < 1e-3);
        assert!(z.rings.iter().all(|r| r.opacity == 0.0));
        assert!((z.word_tracking - 0.6).abs() < 1e-3 && z.word_blur.abs() < 1e-3);
    }

    #[test]
    fn the_core_overshoots_to_2_2_and_faces_are_staggered() {
        let peak = (0..=700).map(|t| arrival(t as f32, false).core_scale).fold(0.0, f32::max);
        assert!((peak - CORE_PEAK).abs() < 0.05, "{peak}");
        let first_seen = |i: usize| (0..700).find(|t| arrival(*t as f32, false).faces[i].opacity > 0.0).unwrap();
        assert_eq!(first_seen(1) - first_seen(0), 70);
        assert_eq!(first_seen(2) - first_seen(1), 70);
        let ring_seen = |i: usize| (0..700).find(|t| arrival(*t as f32, false).rings[i].opacity > 0.0).unwrap();
        assert_eq!(ring_seen(1) - ring_seen(0), 120);
    }

    #[test]
    fn reduced_motion_skips_everything() {
        assert!(arrival(0.0, true).done);
        assert_eq!(card_rise(0.0, 5, true), (0.0, 1.0));
        assert_eq!(tween(0.0, 10.0, 0.0, 200.0, true), 10.0);
        assert!(reduced(MotionPref::System, true));
        assert!(!reduced(MotionPref::Full, true));
        assert!(reduced(MotionPref::Reduced, false));
    }

    #[test]
    fn curves() {
        assert!(ease(0.0).abs() < 1e-3 && (ease(1.0) - 1.0).abs() < 1e-3);
        assert!(ease(0.5) > 0.5, "Vigil's ease is front-loaded");
        let peak = (0..1000).map(|i| Spring::SNAPPY.value(i as f32 / 1000.0)).fold(0.0, f32::max);
        assert!(peak > 1.0 && peak < 1.1, "a small overshoot: {peak}");
        let over = Spring { stiffness: 100.0, damping: 40.0 };
        assert!((over.value(3.0) - 1.0).abs() < 0.01);
        let (dy0, _) = card_rise(0.0, 2, false);
        assert_eq!(dy0, CARD_RISE_PX);
        assert_eq!(card_rise(2.0 * CARD_STAGGER_MS + CARD_RISE_MS, 2, false), (0.0, 1.0));
    }
}
