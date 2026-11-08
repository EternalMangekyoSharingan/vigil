//! Drawing the Vigil mark and the arrival from `vigil_ui_core::motion`'s geometry.
//!
//! One painter draws every frame of the arrival *and* the rail logo, so the arrival's
//! last frame and the logo are the same pixels: the hand-off cannot be seen.

use gpui::{fill, point, px, size, Bounds, Hsla, PathBuilder, Pixels, Point, SharedString, TextAlign, TextRun, Window};
use std::f32::consts::TAU;
use vigil_ui_core::motion::{self, MarkFrame, CORE_COLOUR, CORE_RATIO, FACES, FACE_COLOURS, STROKE_COLOUR};

pub fn hsla(rgb: u32, alpha: f32) -> Hsla {
    let mut h: Hsla = gpui::rgb(rgb).into();
    h.a = alpha.clamp(0.0, 1.0);
    h
}

fn pt(o: Point<Pixels>, (x, y): (f32, f32)) -> Point<Pixels> {
    point(o.x + px(x), o.y + px(y))
}

/// Paint `m`, whose coordinates are relative to `origin`.
pub fn paint(w: &mut Window, origin: Point<Pixels>, m: &MarkFrame) {
    let centre = (m.cx, m.cy);
    // Faces: the centre, then the outline from one corner to the next two corners away.
    for (i, face) in FACES.iter().enumerate() {
        let a = m.face_alpha[i];
        if a <= 0.0 {
            continue;
        }
        let mut b = PathBuilder::fill();
        b.move_to(pt(origin, centre));
        for (x, y) in m.arc(face[0], face[1], 12).into_iter().chain(m.arc(face[1], face[2], 12).into_iter().skip(1)) {
            b.line_to(pt(origin, (x, y)));
        }
        b.close();
        if let Ok(p) = b.build() {
            w.paint_path(p, hsla(FACE_COLOURS[i], a));
        }
    }
    let width = (m.radius / 28.0).clamp(1.0, 1.8);
    if m.stroke_alpha > 0.0 {
        // The traced outline (a partial sweep while it is being drawn).
        if m.sweep > 0.0 {
            let steps = (96.0 * m.sweep).ceil().max(2.0) as usize;
            let start = motion::vertex_angle(0);
            let mut b = PathBuilder::stroke(px(width));
            for i in 0..=steps {
                let p = m.outline(start + TAU * m.sweep * i as f32 / steps as f32);
                if i == 0 {
                    b.move_to(pt(origin, p));
                } else {
                    b.line_to(pt(origin, p));
                }
            }
            if let Ok(p) = b.build() {
                w.paint_path(p, hsla(STROKE_COLOUR, m.stroke_alpha));
            }
        }
        // The three inner edges, growing from the centre.
        let mut b = PathBuilder::stroke(px(width));
        let mut any = false;
        for (j, k) in [1usize, 3, 5].into_iter().enumerate() {
            if m.edges[j] <= 0.0 {
                continue;
            }
            any = true;
            let (x, y) = m.outline(motion::vertex_angle(k));
            let e = m.edges[j];
            b.move_to(pt(origin, centre));
            b.line_to(pt(origin, (m.cx + (x - m.cx) * e, m.cy + (y - m.cy) * e)));
        }
        if any {
            if let Ok(p) = b.build() {
                w.paint_path(p, hsla(STROKE_COLOUR, m.stroke_alpha));
            }
        }
    }
    if m.core_scale > 0.0 {
        let r = m.radius * CORE_RATIO * m.core_scale;
        let c = pt(origin, centre);
        w.paint_quad(
            fill(Bounds::new(point(c.x - px(r), c.y - px(r)), size(px(2.0 * r), px(2.0 * r))), hsla(CORE_COLOUR, 1.0))
                .corner_radii(px(r)),
        );
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
