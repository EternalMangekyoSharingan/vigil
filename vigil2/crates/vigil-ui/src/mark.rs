//! Drawing the Vigil mark and the arrival from `vigil_ui_core::motion`'s geometry.
//!
//! One painter draws every frame of the arrival *and* the rail logo, so the arrival's
//! last frame and the logo are the same pixels: the hand-off cannot be seen.

use gpui::{
    fill, point, px, quad, size, BorderStyle, Bounds, Hsla, PathBuilder, Pixels, Point, SharedString, TextAlign,
    TextRun, Window,
};
use vigil_ui_core::motion::{
    self, MarkFrame, CORE_COLOUR, CORE_RATIO, CORE_RIM, FACE_COLOURS, HIGHLIGHT, STROKE_COLOUR, TILE_SHADE,
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

fn circle(w: &mut Window, c: Point<Pixels>, r: f32, colour: Hsla) {
    w.paint_quad(
        fill(Bounds::new(point(c.x - px(r), c.y - px(r)), size(px(2.0 * r), px(2.0 * r))), colour).corner_radii(px(r)),
    );
}

/// Paint `m`, whose coordinates are relative to `origin`.
pub fn paint(w: &mut Window, origin: Point<Pixels>, m: &MarkFrame) {
    // Faces back to front (left, right, top), each as 2 × 2 tiles in their own shades.
    for i in [2usize, 1, 0] {
        for (j, tone) in TILE_SHADE[i].iter().enumerate() {
            let k = m.tiles[i * 4 + j];
            if k <= 0.0 {
                continue;
            }
            let q = m.tile_quad(i, j);
            let mut b = PathBuilder::fill();
            b.move_to(pt(origin, q[0]));
            for c in &q[1..] {
                b.line_to(pt(origin, *c));
            }
            b.close();
            if let Ok(p) = b.build() {
                w.paint_path(p, hsla(shade(FACE_COLOURS[i], *tone), (k * 1.6).min(1.0)));
            }
        }
    }
    let width = (m.radius / 26.0).clamp(0.8, 1.8);
    // The light rim along the two top edges, where the light falls.
    if m.highlight > 0.0 && m.fold.iter().all(|f| *f > 0.98) {
        let mut b = PathBuilder::stroke(px(width));
        b.move_to(pt(origin, m.corner_px(5)));
        b.line_to(pt(origin, m.corner_px(0)));
        b.line_to(pt(origin, m.corner_px(1)));
        if let Ok(p) = b.build() {
            w.paint_path(p, hsla(HIGHLIGHT, 0.75 * m.highlight));
        }
    }
    // The traced outline: corner to corner, clockwise from the top.
    if m.stroke_alpha > 0.0 && m.sweep > 0.0 {
        let mut b = PathBuilder::stroke(px(width));
        b.move_to(pt(origin, m.corner_px(0)));
        let total = 6.0 * m.sweep;
        for e in 0..6 {
            let part = (total - e as f32).clamp(0.0, 1.0);
            if part <= 0.0 {
                break;
            }
            let (a, c) = (m.corner_px(e), m.corner_px(e + 1));
            b.line_to(pt(origin, (a.0 + (c.0 - a.0) * part, a.1 + (c.1 - a.1) * part)));
        }
        if let Ok(p) = b.build() {
            w.paint_path(p, hsla(STROKE_COLOUR, m.stroke_alpha));
        }
    }
    // The core: a darker rim, the orange body, and a small highlight.
    let c = pt(origin, (m.cx, m.cy));
    let r = m.radius * CORE_RATIO;
    if m.ring.1 > 0.0 {
        let rr = r * m.ring.0;
        w.paint_quad(quad(
            Bounds::new(point(c.x - px(rr), c.y - px(rr)), size(px(2.0 * rr), px(2.0 * rr))),
            px(rr),
            Hsla::transparent_black(),
            px(width * 0.8),
            hsla(CORE_COLOUR, m.ring.1),
            BorderStyle::Solid,
        ));
    }
    if m.core_scale > 0.0 {
        let s = m.core_scale;
        circle(w, c, r * s, hsla(CORE_RIM, 1.0));
        circle(w, c, r * 0.74 * s, hsla(CORE_COLOUR, 1.0));
        circle(w, point(c.x - px(r * 0.22 * s), c.y - px(r * 0.22 * s)), r * 0.2 * s, hsla(0xffe2c2, 0.85));
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
