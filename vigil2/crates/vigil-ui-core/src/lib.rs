//! The parts of Vigil's app that do not depend on the UI toolkit.
//!
//! The toolkit spike (docs/DECISIONS.md) picked GPUI provisionally; the decision is
//! confirmed on the owner's own hardware. Keeping the theme, keymap, palette, motion
//! curves and settings here means a toolkit change rewrites only the drawing code, and
//! all of this is tested without a display.

pub mod areas;
pub mod keymap;
pub mod motion;
pub mod palette;
pub mod settings;
pub mod theme;
