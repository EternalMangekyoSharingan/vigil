//! Small building blocks shared by every view: colours, cards, chips, buttons, and the
//! enter animations (fade and rise on a spring, staggered rows, sliding panels).
//!
//! Animations use GPUI's keyed animations: an element animates when it first appears
//! under an id. Views put a counter that changes on navigation into the id, so entering an
//! area or a tab replays its entrance; data refreshes keep the id and do not.

use gpui::{
    div, prelude::*, px, Animation, AnimationElement, AnimationExt, Div, ElementId, Hsla, SharedString, Stateful,
};
use std::time::Duration;
use vigil_ui_core::motion::{self, Spring};
use vigil_ui_core::theme::{Rgba, Theme};

pub fn c(x: Rgba) -> Hsla {
    gpui::rgba(x.0).into()
}

pub fn ca(x: Rgba, alpha: f32) -> Hsla {
    let mut h = c(x);
    h.a *= alpha.clamp(0.0, 1.0);
    h
}

pub fn id(name: &'static str, n: u64) -> ElementId {
    ElementId::NamedInteger(name.into(), n)
}

pub fn id2(name: &'static str, a: u64, b: u64) -> ElementId {
    ElementId::NamedInteger(SharedString::from(format!("{name}-{a}")), b)
}

/// The one surface: a card with a hairline border.
pub fn card(t: &Theme) -> Div {
    div().rounded(px(t.radius)).bg(c(t.bg[2])).border_1().border_color(c(t.line[0])).flex().flex_col()
}

pub fn card_title(t: &Theme, title: impl Into<SharedString>) -> Div {
    div().text_size(px(13.0)).text_color(c(t.text[1])).child(title.into())
}

/// A small label with a tinted background: "Live", "Hidden", a state.
pub fn chip(text: impl Into<SharedString>, fg: Rgba) -> Div {
    div()
        .px(px(7.0))
        .py(px(1.0))
        .rounded(px(5.0))
        .bg(ca(fg, 0.14))
        .text_color(c(fg))
        .text_size(px(11.0))
        .child(text.into())
}

/// A button: hover lifts the background, press dims it.
pub fn button(t: &Theme, id: impl Into<ElementId>, label: impl Into<SharedString>, primary: bool) -> Stateful<Div> {
    let (bg, fg) = if primary { (t.accent, Rgba::rgb(0x1a1209)) } else { (t.bg[3], t.text[0]) };
    let hover = if primary { t.accent_hi } else { t.bg[4] };
    div()
        .id(id)
        .h(px(30.0))
        .px(px(12.0))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(t.radius_sm))
        .bg(c(bg))
        .text_color(c(fg))
        .text_size(px(12.5))
        .cursor_pointer()
        .hover(move |s| s.bg(c(hover)))
        .active(|s| s.opacity(0.82))
        .child(label.into())
}

/// Fade in and rise into place on a smooth spring, after `delay_ms`.
pub fn enter<E: IntoElement + Styled + 'static>(
    el: E,
    key: ElementId,
    delay_ms: f32,
    rise: f32,
    reduced: bool,
) -> AnimationElement<E> {
    let total = motion::AREA_MS + delay_ms;
    let curve = motion::delayed(delay_ms, total, Spring::SMOOTH.easing(motion::AREA_MS));
    let anim = if reduced {
        Animation::new(Duration::from_millis(1))
    } else {
        Animation::new(Duration::from_millis(total as u64)).with_easing(curve)
    };
    el.with_animation(key, anim, move |el, d| el.opacity(d.clamp(0.0, 1.0)).relative().top(px(rise * (1.0 - d))))
}

/// List rows: each a little after the one above, the first few only.
pub fn row_enter<E: IntoElement + Styled + 'static>(
    el: E,
    key: ElementId,
    i: usize,
    reduced: bool,
) -> AnimationElement<E> {
    let delay = i.min(motion::ROW_STAGGER_MAX) as f32 * motion::ROW_STAGGER_MS;
    enter(el, key, delay, 6.0, reduced)
}

/// A panel sliding in from the right on a snappy spring.
pub fn slide_in<E: IntoElement + Styled + 'static>(el: E, key: ElementId, reduced: bool) -> AnimationElement<E> {
    let anim = if reduced {
        Animation::new(Duration::from_millis(1))
    } else {
        Animation::new(Duration::from_millis(motion::PANEL_MS as u64))
            .with_easing(Spring::SNAPPY.easing(motion::PANEL_MS))
    };
    el.with_animation(key, anim, |el, d| {
        el.opacity(d.clamp(0.0, 1.0)).relative().left(px(motion::PANEL_SLIDE_PX * (1.0 - d)))
    })
}

/// A key cap, for shortcut hints.
pub fn kbd(t: &Theme, text: impl Into<SharedString>) -> Div {
    div()
        .px(px(5.0))
        .rounded(px(4.0))
        .border_1()
        .border_color(c(t.line[1]))
        .text_size(px(10.5))
        .text_color(c(t.text[2]))
        .child(text.into())
}

/// "3 min ago".
pub fn ago(ts: f64) -> String {
    let d = vigil_model::finding::now() - ts;
    if d < 5.0 {
        "just now".into()
    } else {
        format!("{} ago", vigil_model::wording::span(d, true))
    }
}
