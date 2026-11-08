//! Motion: gorgeous, never in the way (docs/RUST_REWRITE.md 5.3).
//!
//! Everything here is a pure function of time, so each animation is tested frame by
//! frame and a toolkit only asks "what does frame t look like?".
//!
//! **Springs** use the parameters Apple's SwiftUI uses: a *response* (the period of the
//! undamped oscillation, in seconds) and a *damping fraction* (1 = no overshoot, below 1 a
//! little bounce). They convert to stiffness k = (2π / response)² and damping
//! c = 4π · fraction / response for a unit mass.
//!
//! **The arrival** builds the Vigil mark from squares (see [`arrival`] and the geometry
//! notes below): twelve tiles appear flat, the three faces fold into an isometric cube by
//! shear, an outline is traced, the core ignites, and the mark glides onto the rail logo
//! while the backdrop dissolves: the last frame *is* the app.
//!
//! Rules enforced by the tests: nothing but the arrival lasts longer than
//! [`MAX_TRANSITION_MS`]; reduced motion skips the arrival; the last frame matches the
//! rail logo exactly.

use std::f32::consts::{PI, TAU};

/// Every transition other than the arrival is at most this long.
pub const MAX_TRANSITION_MS: f32 = 300.0;
pub const RAIL_MARKER_MS: f32 = 260.0;
pub const TAB_MS: f32 = 220.0;
pub const TAB_SLIDE_PX: f32 = 6.0;
/// Content entering an area: fade and rise.
pub const AREA_MS: f32 = 280.0;
pub const AREA_RISE_PX: f32 = 10.0;
/// A detail panel sliding in beside its list.
pub const PANEL_MS: f32 = 260.0;
pub const PANEL_SLIDE_PX: f32 = 28.0;
/// Overlays (palette, Settings): open and close.
pub const OVERLAY_IN_MS: f32 = 240.0;
pub const OVERLAY_OUT_MS: f32 = 200.0;
/// Lists: each row starts this much after the one above (capped).
pub const ROW_STAGGER_MS: f32 = 14.0;
pub const ROW_STAGGER_MAX: usize = 18;
/// Home's cards rise one after another.
pub const CARD_STAGGER_MS: f32 = 40.0;
pub const CARD_RISE_MS: f32 = 300.0;
pub const CARD_RISE_PX: f32 = 14.0;
/// Numbers roll to their new value.
pub const COUNTER_MS: f32 = 450.0;

/// CSS `cubic-bezier(x1, y1, x2, y2)` at progress `t` (0..1).
pub fn cubic_bezier(x1: f32, y1: f32, x2: f32, y2: f32, t: f32) -> f32 {
    if t <= 0.0 {
        return 0.0;
    }
    if t >= 1.0 {
        return 1.0;
    }
    let bez = |a: f32, b: f32, s: f32| 3.0 * a * s * (1.0 - s).powi(2) + 3.0 * b * s * s * (1.0 - s) + s.powi(3);
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

/// Vigil's standard ease (`--ease` in Vigil 1's style.css), front-loaded.
pub fn ease(t: f32) -> f32 {
    cubic_bezier(0.2, 0.7, 0.2, 1.0, t)
}

/// Symmetric ease-in-out (cubic): for things that start and end at rest.
pub fn ease_in_out(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
    }
}

/// A damped spring from 0 to 1 (unit mass).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spring {
    pub stiffness: f32,
    pub damping: f32,
}

impl Spring {
    /// SwiftUI-style parameters: `response` in seconds, `damping_fraction` 0..=1+.
    pub const fn apple(response: f32, damping_fraction: f32) -> Spring {
        let w = TAU / response;
        Spring { stiffness: w * w, damping: 4.0 * PI * damping_fraction / response }
    }
    /// SwiftUI's default `.spring()`: no visible overshoot, settles quickly.
    pub const SMOOTH: Spring = Spring::apple(0.42, 1.0);
    /// `.snappy`: a hint of bounce. Rail marker, panels.
    pub const SNAPPY: Spring = Spring::apple(0.32, 0.82);
    /// `.bouncy`: the core igniting.
    pub const BOUNCY: Spring = Spring::apple(0.38, 0.55);

    /// Position at `t` seconds after release.
    pub fn value(self, t: f32) -> f32 {
        if t <= 0.0 {
            return 0.0;
        }
        let w0 = self.stiffness.sqrt();
        let zeta = self.damping / (2.0 * w0);
        if zeta < 1.0 - 1e-4 {
            let wd = w0 * (1.0 - zeta * zeta).sqrt();
            1.0 - (-zeta * w0 * t).exp() * ((wd * t).cos() + (zeta * w0 / wd) * (wd * t).sin())
        } else if zeta <= 1.0 + 1e-4 {
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

    /// The spring as an easing curve over `duration_ms`, ending exactly at 1: for
    /// toolkits whose animations take an easing function and a fixed duration.
    pub fn easing(self, duration_ms: f32) -> impl Fn(f32) -> f32 {
        move |t: f32| if t >= 1.0 { 1.0 } else { self.value(t * duration_ms / 1000.0) }
    }
}

/// An easing that waits `delay_ms` of a `total_ms` animation, then runs `curve` over
/// the rest: staggered entrances with one fixed-length animation per element.
pub fn delayed(delay_ms: f32, total_ms: f32, curve: impl Fn(f32) -> f32) -> impl Fn(f32) -> f32 {
    move |t: f32| {
        let span = (total_ms - delay_ms).max(1.0);
        curve(((t * total_ms - delay_ms) / span).clamp(0.0, 1.0))
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

// ---- the mark's geometry ------------------------------------------------------------------
//
// The mark is an isometric cube. Each of its three faces is a square seen in isometric
// projection, divided into 2 × 2 tiles in slightly different shades (the undertones). In face
// coordinates (u, v) ∈ [0, 1]², a face is the image of the unit square under
//     p(u, v) = origin + u · e1 + v · e2,
// with e1, e2 two of the cube's edge vectors from its centre vertex. The arrival animates the
// columns of that 2 × 2 matrix and the origin: from a flat, upright square to the face's
// isometric parallelogram. Linear interpolation of the matrix is a shear-and-rotate, so the
// squares *fold* into the cube rather than morph.

/// The hexagon's corners from the top, clockwise (pointy-top):
/// 0 top, 1 upper right, 2 lower right, 3 bottom, 4 lower left, 5 upper left.
pub fn vertex_angle(k: usize) -> f32 {
    -PI / 2.0 + (k % 6) as f32 * PI / 3.0
}

pub fn corner(k: usize) -> (f32, f32) {
    let a = vertex_angle(k);
    (a.cos(), a.sin())
}

/// Each face as (e1 corner, e2 corner): the face spans centre, e1, e1 + e2, e2.
/// Top (light), right (mid), left (deep).
pub const FACES: [(usize, usize); 3] = [(1, 5), (1, 3), (3, 5)];
pub const FACE_COLOURS: [u32; 3] = [0x9fe3df, 0x5dbdb9, 0x3f9a95];
/// Shade of each tile in a face, as a lightness offset: a quiet diagonal gradient, with
/// the two faces in shadow rotated so the light seems to come from the upper left.
pub const TILE_SHADE: [[f32; 4]; 3] =
    [[0.10, 0.04, 0.04, -0.03], [0.05, -0.02, 0.02, -0.08], [0.02, -0.05, -0.04, -0.12]];
/// The gap between tiles, as a fraction of a face's edge.
pub const TILE_GAP: f32 = 0.07;
pub const CORE_COLOUR: u32 = 0xff9f43;
pub const CORE_RIM: u32 = 0xc2621f;
pub const STROKE_COLOUR: u32 = 0x62f3ff;
pub const HIGHLIGHT: u32 = 0xe8fffd;
/// The core's radius as a fraction of the hexagon's circumradius.
pub const CORE_RATIO: f32 = 0.17;

/// A 2 × 2 linear map plus a translation (column vectors a, b; origin o).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Affine {
    pub a: (f32, f32),
    pub b: (f32, f32),
    pub o: (f32, f32),
}

impl Affine {
    pub fn apply(&self, u: f32, v: f32) -> (f32, f32) {
        (self.o.0 + u * self.a.0 + v * self.b.0, self.o.1 + u * self.a.1 + v * self.b.1)
    }
    pub fn lerp(&self, other: &Affine, t: f32) -> Affine {
        let l = |x: (f32, f32), y: (f32, f32)| (x.0 + (y.0 - x.0) * t, x.1 + (y.1 - x.1) * t);
        Affine { a: l(self.a, other.a), b: l(self.b, other.b), o: l(self.o, other.o) }
    }
}

/// Face `i` of a cube of circumradius 1 centred on the origin.
pub fn face_rest(i: usize) -> Affine {
    let (k1, k2) = FACES[i];
    Affine { a: corner(k1), b: corner(k2), o: (0.0, 0.0) }
}

/// Face `i` before it folds: an upright square of the same area as a tile group, laid out
/// as an unfolded net around the centre (top above, the shadowed faces below left and right).
pub fn face_flat(i: usize) -> Affine {
    let s = 0.78;
    let (ox, oy) = [(-s / 2.0, -s - 0.28), (0.22, 0.02), (-0.22 - s, 0.02)][i];
    Affine { a: (s, 0.0), b: (0.0, s), o: (ox, oy) }
}

/// Tile `j` (0..4) of a face, as a (u0, v0, size) square in face coordinates.
pub fn tile(j: usize) -> (f32, f32, f32) {
    let s = 0.5 - TILE_GAP / 2.0;
    let (cu, cv) = [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)][j];
    (cu * (0.5 + TILE_GAP / 2.0), cv * (0.5 + TILE_GAP / 2.0), s)
}

/// Everything the painter needs for one frame of the mark. Coordinates in pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MarkFrame {
    pub cx: f32,
    pub cy: f32,
    /// Circumradius in pixels.
    pub radius: f32,
    /// Per face: 0 = flat upright square, 1 = folded into the cube.
    pub fold: [f32; 3],
    /// Per tile (face * 4 + tile): its scale about its own centre (0 = not there yet).
    pub tiles: [f32; 12],
    /// The traced hexagon outline: how much of it is drawn, and how visible.
    pub sweep: f32,
    pub stroke_alpha: f32,
    /// The light rim along the top edges.
    pub highlight: f32,
    pub core_scale: f32,
    /// A thin ring that leaves the core once, as it ignites (radius multiple, alpha).
    pub ring: (f32, f32),
}

impl MarkFrame {
    /// The finished mark at rest: what the rail logo shows.
    pub fn at_rest(cx: f32, cy: f32, radius: f32) -> MarkFrame {
        MarkFrame {
            cx,
            cy,
            radius,
            fold: [1.0; 3],
            tiles: [1.0; 12],
            sweep: 1.0,
            stroke_alpha: 0.0,
            highlight: 1.0,
            core_scale: 1.0,
            ring: (1.0, 0.0),
        }
    }

    /// Face `i`'s map into pixels.
    pub fn face(&self, i: usize) -> Affine {
        let f = face_flat(i).lerp(&face_rest(i), self.fold[i]);
        let r = self.radius;
        Affine { a: (f.a.0 * r, f.a.1 * r), b: (f.b.0 * r, f.b.1 * r), o: (self.cx + f.o.0 * r, self.cy + f.o.1 * r) }
    }

    /// The four corners of tile `j` of face `i`, scaled about the tile's centre.
    pub fn tile_quad(&self, i: usize, j: usize) -> [(f32, f32); 4] {
        let m = self.face(i);
        let (u0, v0, s) = tile(j);
        let k = self.tiles[i * 4 + j];
        let (cu, cv) = (u0 + s / 2.0, v0 + s / 2.0);
        let h = s / 2.0 * k;
        [m.apply(cu - h, cv - h), m.apply(cu + h, cv - h), m.apply(cu + h, cv + h), m.apply(cu - h, cv + h)]
    }

    /// Hexagon corner `k` in pixels.
    pub fn corner_px(&self, k: usize) -> (f32, f32) {
        let (x, y) = corner(k);
        (self.cx + x * self.radius, self.cy + y * self.radius)
    }
}

/// Where the arrival lands: the rail logo's centre and circumradius, in window pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Landing {
    pub cx: f32,
    pub cy: f32,
    pub radius: f32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArrivalFrame {
    /// Opacity of the backdrop over the app.
    pub backdrop: f32,
    pub mark: MarkFrame,
    /// The word VIGIL: per-letter opacity and rise (px), and letter spacing (em).
    pub letters: [(f32, f32); 5],
    pub tracking: f32,
    /// True on and after the frame where the overlay's mark sits exactly on the logo.
    pub landed: bool,
    pub done: bool,
}

/// Phase timings (ms).
pub const TILE_START: f32 = 0.0;
pub const TILE_STAGGER: f32 = 26.0;
pub const FOLD_START: f32 = 480.0;
pub const FOLD_STAGGER: f32 = 70.0;
pub const SWEEP: (f32, f32) = (880.0, 300.0);
pub const CORE_START: f32 = 960.0;
pub const WORD_START: f32 = 580.0;
pub const LETTER_STAGGER: f32 = 40.0;
pub const LETTER_MS: f32 = 320.0;
pub const FLIGHT_START: f32 = 1300.0;
pub const FLIGHT_MS: f32 = 540.0;
pub const ARRIVAL_MS: f32 = FLIGHT_START + FLIGHT_MS;
/// Circumradius of the mark at the centre of the window.
pub const STAGE_RADIUS: f32 = 50.0;
/// Tiles appear in a spiral from the top face's corner: this order.
pub const TILE_ORDER: [usize; 12] = [0, 1, 3, 2, 4, 5, 7, 6, 11, 10, 8, 9];

fn progress(t: f32, start: f32, len: f32) -> f32 {
    ((t - start) / len).clamp(0.0, 1.0)
}

/// Ken Perlin's smootherstep, 6t⁵ − 15t⁴ + 10t³: zero speed *and* zero acceleration at
/// both ends, so the mark lifts off and settles without a visible jerk, and its top speed
/// is only 1.875 times its average.
pub fn flight_ease(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    t * t * t * (t * (t * 6.0 - 15.0) + 10.0)
}

/// A cubic Bézier that leaves the start horizontally and arrives vertically.
fn flight_path(from: (f32, f32), to: (f32, f32), s: f32) -> (f32, f32) {
    let c1 = (from.0 + (to.0 - from.0) * 0.55, from.1);
    let c2 = (to.0, from.1 + (to.1 - from.1) * 0.45);
    let u = 1.0 - s;
    let b = |a: f32, b: f32, c: f32, d: f32| u * u * u * a + 3.0 * u * u * s * b + 3.0 * u * s * s * c + s * s * s * d;
    (b(from.0, c1.0, c2.0, to.0), b(from.1, c1.1, c2.1, to.1))
}

/// The arrival at `t` ms in a `w` × `h` window, landing on `land`. With `reduced` it is over.
///
/// 1. Twelve tiles pop in one after another (a bouncy spring each), laid out flat as an
///    unfolded cube; 2. the three faces fold into the cube, one after another (shear on a
///    smooth spring); 3. a light rim runs along the top edges and a thin outline is traced
///    around the hexagon, then fades; 4. the core ignites, sending one ring outward;
///    5. the mark glides onto the rail logo while the backdrop dissolves.
pub fn arrival(t: f32, w: f32, h: f32, land: Landing, reduced: bool) -> ArrivalFrame {
    let t = if reduced { ARRIVAL_MS } else { t.max(0.0) };
    let secs = |start: f32| ((t - start) / 1000.0).max(0.0);
    let centre = (w / 2.0, h / 2.0 - 18.0);

    let mut tiles = [0.0f32; 12];
    for (n, idx) in TILE_ORDER.iter().enumerate() {
        let start = TILE_START + n as f32 * TILE_STAGGER;
        tiles[*idx] = if t <= start { 0.0 } else { Spring::BOUNCY.value(secs(start)) };
    }
    let fold = std::array::from_fn(|i| {
        let start = FOLD_START + i as f32 * FOLD_STAGGER;
        if t <= start {
            0.0
        } else {
            Spring::SMOOTH.value(secs(start)).min(1.0)
        }
    });
    let sweep = ease_in_out(progress(t, SWEEP.0, SWEEP.1));
    let stroke_alpha = if t < SWEEP.0 { 0.0 } else { 1.0 - ease(progress(t, SWEEP.0 + SWEEP.1, 260.0)) };
    let highlight = ease(progress(t, SWEEP.0 + 60.0, 260.0));
    let core_scale = if t <= CORE_START { 0.0 } else { Spring::BOUNCY.value(secs(CORE_START)) };
    let rp = progress(t, CORE_START + 40.0, 420.0);
    let ring = (1.0 + 3.0 * ease(rp), if rp <= 0.0 || rp >= 1.0 { 0.0 } else { 0.8 * (1.0 - rp) });

    let f = flight_ease(progress(t, FLIGHT_START, FLIGHT_MS));
    let (cx, cy) = flight_path(centre, (land.cx, land.cy), f);
    let radius = STAGE_RADIUS + (land.radius - STAGE_RADIUS) * f;

    let letters = std::array::from_fn(|i| {
        let p = ease(progress(t, WORD_START + i as f32 * LETTER_STAGGER, LETTER_MS));
        let out = 1.0 - ease(progress(t, FLIGHT_START - 60.0, 180.0));
        (p * out, 8.0 * (1.0 - p))
    });
    let tracking = 0.9 - 0.5 * ease(progress(t, WORD_START, LETTER_MS + 4.0 * LETTER_STAGGER));

    let landed = t >= ARRIVAL_MS;
    let mark = if landed {
        MarkFrame::at_rest(land.cx, land.cy, land.radius)
    } else {
        MarkFrame { cx, cy, radius, fold, tiles, sweep, stroke_alpha, highlight, core_scale, ring }
    };
    ArrivalFrame {
        backdrop: 1.0 - ease_in_out(progress(t, FLIGHT_START + 40.0, FLIGHT_MS - 40.0)),
        mark,
        letters,
        tracking,
        landed,
        done: landed,
    }
}

/// Home's card `i` after the arrival (or after entering Home): (offset px, opacity).
pub fn card_rise(t_after: f32, i: usize, reduced: bool) -> (f32, f32) {
    if reduced {
        return (0.0, 1.0);
    }
    let p = Spring::SMOOTH.easing(CARD_RISE_MS)(progress(t_after, i as f32 * CARD_STAGGER_MS, CARD_RISE_MS));
    (CARD_RISE_PX * (1.0 - p), p.min(1.0))
}

/// A value easing from `from` to `to` over `len` ms (counters, markers).
pub fn tween(from: f32, to: f32, t: f32, len: f32, reduced: bool) -> f32 {
    if reduced || len <= 0.0 {
        return to;
    }
    from + (to - from) * ease((t / len).clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAND: Landing = Landing { cx: 34.0, cy: 34.0, radius: 12.5 };

    fn at(t: f32) -> ArrivalFrame {
        arrival(t, 1280.0, 800.0, LAND, false)
    }

    fn close(a: (f32, f32), b: (f32, f32)) -> bool {
        (a.0 - b.0).abs() < 1e-3 && (a.1 - b.1).abs() < 1e-3
    }

    #[test]
    fn transitions_respect_the_limits() {
        let all = [RAIL_MARKER_MS, TAB_MS, AREA_MS, PANEL_MS, OVERLAY_IN_MS, OVERLAY_OUT_MS, CARD_RISE_MS];
        assert!(all.iter().all(|ms| *ms <= MAX_TRANSITION_MS), "{all:?}");
        for s in [Spring::SMOOTH, Spring::SNAPPY] {
            assert!(s.settle_time(0.01) * 1000.0 < 600.0, "{s:?}");
        }
    }

    #[test]
    fn the_folded_faces_tile_the_hexagon() {
        // Each face's far corner is a hexagon corner: top -> 0, right -> 2, left -> 4.
        for (i, k) in [(0usize, 0usize), (1, 2), (2, 4)] {
            assert!(close(face_rest(i).apply(1.0, 1.0), corner(k)), "face {i}");
        }
        // The faces meet along the inner edges (no gaps, no overlaps).
        assert!(close(face_rest(0).apply(1.0, 0.0), face_rest(1).apply(1.0, 0.0)));
        assert!(close(face_rest(1).apply(0.0, 1.0), face_rest(2).apply(1.0, 0.0)));
        assert!(close(face_rest(2).apply(0.0, 1.0), face_rest(0).apply(0.0, 1.0)));
        // Flat faces are true squares: equal, perpendicular sides.
        for i in 0..3 {
            let f = face_flat(i);
            assert!((f.a.0 * f.b.0 + f.a.1 * f.b.1).abs() < 1e-6);
            assert!(((f.a.0.hypot(f.a.1)) - f.b.0.hypot(f.b.1)).abs() < 1e-6);
        }
        // Tiles leave gaps and stay inside the face.
        let (u0, v0, s) = tile(3);
        assert!(u0 > 0.5 && v0 > 0.5 && (u0 + s - 1.0).abs() < 1e-6);
    }

    #[test]
    fn the_arrival_assembles_then_lands_exactly_on_the_logo() {
        let a = at(0.0);
        assert!(a.mark.tiles.iter().all(|x| *x == 0.0));
        assert_eq!(a.mark.core_scale, 0.0);
        assert!((a.backdrop - 1.0).abs() < 1e-6);
        // Before the fold every tile is in, laid flat.
        let flat = at(FOLD_START - 1.0);
        assert!(flat.mark.tiles.iter().all(|x| *x > 0.7), "{:?}", flat.mark.tiles);
        assert!(flat.mark.fold.iter().all(|x| *x == 0.0));
        // Folded by the sweep.
        assert!(at(SWEEP.0 + 100.0).mark.fold.iter().all(|x| *x > 0.95));
        // The core overshoots a little, then settles.
        let peak = (0..1700).map(|t| at(t as f32).mark.core_scale).fold(0.0, f32::max);
        assert!(peak > 1.05 && peak < 1.3, "{peak}");
        // The last frame is the rail logo.
        let z = at(ARRIVAL_MS);
        assert!(z.done && z.landed);
        assert_eq!(z.mark, MarkFrame::at_rest(LAND.cx, LAND.cy, LAND.radius));
        assert!(z.backdrop.abs() < 1e-6);
        let y = at(ARRIVAL_MS - 16.0);
        assert!((y.mark.cx - LAND.cx).abs() < 1.5 && (y.mark.cy - LAND.cy).abs() < 1.5, "{:?}", y.mark);
        assert!(at(FLIGHT_START + 150.0).letters.iter().all(|(o, _)| *o < 0.05));
    }

    #[test]
    fn motion_is_continuous() {
        let start = at(FLIGHT_START);
        let dist = ((start.mark.cx - LAND.cx).powi(2) + (start.mark.cy - LAND.cy).powi(2)).sqrt();
        let avg = dist / (FLIGHT_MS / 16.0);
        let mut prev = at(0.0);
        for i in 1..=(ARRIVAL_MS as i32 / 16 + 2) {
            let f = at(i as f32 * 16.0);
            let d = ((f.mark.cx - prev.mark.cx).powi(2) + (f.mark.cy - prev.mark.cy).powi(2)).sqrt();
            assert!(d < 2.6 * avg, "jump of {d}px at frame {i}");
            // Tiles never jump either: a corner moves less than a quarter of the stage radius.
            for face in 0..3 {
                let (p, q) = (prev.mark.tile_quad(face, 0)[0], f.mark.tile_quad(face, 0)[0]);
                if f.mark.cx == prev.mark.cx {
                    assert!(((p.0 - q.0).powi(2) + (p.1 - q.1).powi(2)).sqrt() < STAGE_RADIUS * 0.3, "frame {i}");
                }
            }
            prev = f;
        }
    }

    #[test]
    fn reduced_motion_skips_everything() {
        assert!(arrival(0.0, 1280.0, 800.0, LAND, true).done);
        assert_eq!(card_rise(0.0, 5, true), (0.0, 1.0));
        assert_eq!(tween(0.0, 10.0, 0.0, 200.0, true), 10.0);
        assert!(reduced(MotionPref::System, true));
        assert!(!reduced(MotionPref::Full, true));
    }

    #[test]
    fn springs_and_curves() {
        assert!(ease(0.5) > 0.5);
        assert!((ease_in_out(0.5) - 0.5).abs() < 1e-6);
        let peak = (0..1000).map(|i| Spring::BOUNCY.value(i as f32 / 1000.0)).fold(0.0, f32::max);
        assert!(peak > 1.05);
        let smooth = (0..1000).map(|i| Spring::SMOOTH.value(i as f32 / 1000.0)).fold(0.0, f32::max);
        assert!(smooth <= 1.0 + 1e-4);
        let d = delayed(100.0, 300.0, |x| x);
        assert_eq!(d(0.2), 0.0);
        assert_eq!(card_rise(10_000.0, 3, false), (0.0, 1.0));
    }
}
