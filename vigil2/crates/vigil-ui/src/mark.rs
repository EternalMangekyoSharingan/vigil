//! Drawing the Vigil mark and the arrival from `vigil_ui_core::motion`'s geometry.
//!
//! One painter draws every frame of the arrival *and* the rail logo, so the arrival's
//! last frame and the logo are the same pixels: the hand-off cannot be seen.

use gpui::{fill, point, px, Bounds, Hsla, PathBuilder, Pixels, Point, SharedString, TextAlign, TextRun, Window};
use vigil_ui_core::motion::{
    self, MarkFrame, CORE_COLOURS, CORE_SIZE, FACE_COLOURS, HIGHLIGHT, SLOT_COLOUR, SLOT_GAP, STROKE_COLOUR, TILE_SHADE,
};

pub fn hsla(rgb: u32, alpha: f32) -> Hsla {
    let mut h: Hsla = gpui::rgb(rgb).into();
    h.a = alpha.clamp(0.0, 1.0);
    h
}

/// `rgb` lightened (k > 0, toward white) or darkened (k < 0, toward black).
pub fn shade(rgb: u32, k: f32) -> u32 {
    let ch = |shift: u32| {
        let c = ((rgb >> shift) & 0xff) as f32;
        let v = if k >= 0.0 { c + (255.0 - c) * k } else { c * (1.0 + k) };
        (v.round().clamp(0.0, 255.0) as u32) << shift
    };
    ch(16) | ch(8) | ch(0)
}

fn pt(o: Point<Pixels>, (x, y): (f32, f32)) -> Point<Pixels> {
    point(o.x + px(x), o.y + px(y))
}

fn fill_poly(w: &mut Window, o: Point<Pixels>, q: &[(f32, f32)], colour: Hsla) {
    let mut b = PathBuilder::fill();
    b.move_to(pt(o, q[0]));
    for c in &q[1..] {
        b.line_to(pt(o, *c));
    }
    b.close();
    if let Ok(p) = b.build() {
        w.paint_path(p, colour);
    }
}

fn polyline(w: &mut Window, o: Point<Pixels>, q: &[(f32, f32)], width: f32, colour: Hsla) {
    let mut b = PathBuilder::stroke(px(width));
    b.move_to(pt(o, q[0]));
    for c in &q[1..] {
        b.line_to(pt(o, *c));
    }
    if let Ok(p) = b.build() {
        w.paint_path(p, colour);
    }
}

/// Paint `m`, whose coordinates are relative to `origin`.
///
/// The mark: a teal isometric cube (the shell) holding a smaller orange cube (the core)
/// in its near corner, with a dark slot between them. Faces are flat colours, lit from
/// the upper left; a light rim runs along the top edges.
pub fn paint(w: &mut Window, origin: Point<Pixels>, m: &MarkFrame) {
    // The shell, faces back to front (left, right, top): solid once merged, else 2 x 2 tiles.
    for i in [2usize, 1, 0] {
        if m.merge >= 1.0 && m.fold[i] >= 1.0 {
            fill_poly(w, origin, &m.face_quad(i, 0.0, 0.0, 1.0, 1.0), hsla(FACE_COLOURS[i], 1.0));
            continue;
        }
        for (j, tone) in TILE_SHADE[i].iter().enumerate() {
            let k = m.tiles[i * 4 + j];
            if k <= 0.0 {
                continue;
            }
            let colour = hsla(shade(FACE_COLOURS[i], tone * (1.0 - m.merge)), (k * 1.6).min(1.0));
            fill_poly(w, origin, &m.tile_quad(i, j), colour);
        }
    }
    let width = (m.radius / 26.0).clamp(0.8, 1.8);
    let folded = m.fold.iter().all(|f| *f > 0.98);
    // The light rim along the two top edges, where the light falls.
    if m.highlight > 0.0 && folded {
        polyline(
            w,
            origin,
            &[m.corner_px(5), m.corner_px(0), m.corner_px(1)],
            width,
            hsla(HIGHLIGHT, 0.75 * m.highlight),
        );
    }
    // The core: its slot, then its three faces, then its own small rim.
    if m.core_scale > 0.0 && folded {
        let s = CORE_SIZE * m.core_scale;
        let g = (CORE_SIZE + SLOT_GAP) * m.core_scale.min(1.0);
        for i in [2usize, 1, 0] {
            fill_poly(w, origin, &m.face_quad(i, 0.0, 0.0, g, g), hsla(SLOT_COLOUR, 1.0));
        }
        for i in [2usize, 1, 0] {
            fill_poly(w, origin, &m.face_quad(i, 0.0, 0.0, s, s), hsla(CORE_COLOURS[i], 1.0));
        }
        let top = m.face(0);
        polyline(
            w,
            origin,
            &[top.apply(0.0, s), top.apply(s, s), top.apply(s, 0.0)],
            (width * 0.8).max(0.7),
            hsla(0xfff1de, 0.7 * m.highlight),
        );
    }
    // The traced outline: corner to corner, clockwise from the top.
    if m.stroke_alpha > 0.0 && m.sweep > 0.0 {
        let total = 6.0 * m.sweep;
        let mut q = vec![m.corner_px(0)];
        for e in 0..6 {
            let part = (total - e as f32).clamp(0.0, 1.0);
            if part <= 0.0 {
                break;
            }
            let (a, c) = (m.corner_px(e), m.corner_px(e + 1));
            q.push((a.0 + (c.0 - a.0) * part, a.1 + (c.1 - a.1) * part));
        }
        if q.len() > 1 {
            polyline(w, origin, &q, width, hsla(STROKE_COLOUR, m.stroke_alpha));
        }
    }
}

/// The arrival over the whole window, at `t` ms. `land` is where the rail logo is.
pub fn paint_arrival(
    w: &mut Window,
    cx: &mut gpui::App,
    bounds: Bounds<Pixels>,
    t: f32,
    land: motion::Landing,
    bg: u32,
    text: u32,
) {
    let (bw, bh) = (f32::from(bounds.size.width), f32::from(bounds.size.height));
    let f = motion::arrival(t, bw, bh, land, false);
    w.paint_quad(fill(bounds, hsla(bg, f.backdrop)));
    paint(w, bounds.origin, &f.mark);
    // VIGIL, letter by letter, under the mark.
    if f.letters.iter().any(|(o, _)| *o > 0.0) {
        let size_px = 13.0;
        let font = w.text_style().font();
        let lines: Vec<_> = "VIGIL"
            .chars()
            .zip(f.letters)
            .map(|(ch, (op, rise))| {
                let run = TextRun {
                    len: ch.len_utf8(),
                    font: font.clone(),
                    color: hsla(text, op),
                    background_color: None,
                    underline: None,
                    strikethrough: None,
                };
                (w.text_system().shape_line(SharedString::from(ch.to_string()), px(size_px), &[run], None), rise)
            })
            .collect();
        let gap = f.tracking * size_px;
        let total: f32 = lines.iter().map(|(l, _)| f32::from(l.width) + gap).sum::<f32>() - gap;
        let mut x = bw / 2.0 - total / 2.0;
        let y = bh / 2.0 - 18.0 + motion::STAGE_RADIUS + 34.0;
        for (line, rise) in lines {
            let wd = f32::from(line.width);
            let _ = line.paint(pt(bounds.origin, (x, y + rise)), px(18.0), TextAlign::Left, None, w, cx);
            x += wd + gap;
        }
    }
}
