//! Line icons (20×20, 1.5 px strokes), ported from Vigil 1's `vigil/ui/static/suite.js`,
//! served to GPUI as SVG assets ("icons/<name>.svg") and tinted with the text colour.

use gpui::{AssetSource, Result, SharedString};
use std::borrow::Cow;

const ICONS: &[(&str, &[&str])] = &[
    ("home", &["M3.5 9.2 10 4l6.5 5.2", "M5.5 8v7.5h9V8", "M8.5 15.5v-4h3v4"]),
    (
        "network",
        &[
            "M10 10m-1.8 0a1.8 1.8 0 1 0 3.6 0a1.8 1.8 0 1 0-3.6 0",
            "M4.5 5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0",
            "M15.5 5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0",
            "M15.5 15.5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0",
            "M5.6 6.1 8.6 8.8",
            "M14.4 6.1l-3 2.7",
            "M11.4 11.3l3 3",
        ],
    ),
    ("processes", &["M4 4.5h4v3H4z", "M11 9h5v3h-5z", "M11 14h5v3h-5z", "M6 7.5v9h5", "M6 10.5h5"]),
    ("autostart", &["M10 3.5v6", "M6.2 6.2a5.5 5.5 0 1 0 7.6 0"]),
    (
        "files",
        &[
            "M5 3.5h6.5L15 7v9.5H5z",
            "M11.5 3.5V7H15",
            "M10 9.6l2.4 1v1.8c0 1.4-1 2.4-2.4 2.9-1.4-.5-2.4-1.5-2.4-2.9v-1.8z",
        ],
    ),
    ("software", &["M10 3.5l6 3v7l-6 3-6-3v-7z", "M4 6.5l6 3 6-3", "M10 9.5v7", "M7 5l6 3"]),
    ("guard", &["M10 3.5l5.5 2v4.2c0 3.3-2.3 5.6-5.5 6.8-3.2-1.2-5.5-3.5-5.5-6.8V5.5z", "M7.6 10.2l1.7 1.7 3.2-3.4"]),
    (
        "canaries",
        &["M5.5 13c0-3 2.2-5.5 5-5.5H13l2.5-1.5v3l-2 1c0 2.8-2.3 4.5-5 4.5z", "M5.5 13 3.5 15.5", "M12.3 9.6h.01"],
    ),
    ("cases", &["M4 4.5v11", "M4 6.5h9", "M7 10h8", "M5.5 13.5h7"]),
    ("search", &["M8.8 8.8m-4.8 0a4.8 4.8 0 1 0 9.6 0a4.8 4.8 0 1 0-9.6 0", "M12.4 12.4 16 16"]),
    ("keys", &["M3 6h14v8.5H3z", "M5.5 8.5h.01M8.5 8.5h.01M11.5 8.5h.01M14.5 8.5h.01M6.5 12h7"]),
    ("close", &["M5 5l10 10M15 5 5 15"]),
    ("tick", &["M5.2 10.4l3.1 3.1 6.6-6.8"]),
    ("clock", &["M10 10m-6.5 0a6.5 6.5 0 1 0 13 0a6.5 6.5 0 1 0-13 0", "M10 6.6V10l2.4 1.6"]),
    ("out", &["M6 14 14 6", "M8.5 6H14v5.5"]),
    ("in", &["M14 6 6 14", "M6 8.5V14h5.5"]),
    (
        "listen",
        &[
            "M10 10m-1.6 0a1.6 1.6 0 1 0 3.2 0a1.6 1.6 0 1 0-3.2 0",
            "M6.6 6.6a4.8 4.8 0 0 0 0 6.8",
            "M13.4 6.6a4.8 4.8 0 0 1 0 6.8",
        ],
    ),
    ("laptop", &["M4.5 5h11v7.5h-11z", "M2.5 15.5h15"]),
    ("desktop", &["M3 4h14v9.5H3z", "M7.5 16.5h5", "M10 13.5v3"]),
    (
        "thumb",
        &[
            "M7 9.2v7.6",
            "M7 9.2l3-5.1c1-.2 2 .5 2 1.6v2.6h3.4c1 0 1.8.9 1.6 1.9l-1 5c-.2.9-1 1.5-1.9 1.5H7",
            "M3.5 9.2H7v7.6H3.5z",
        ],
    ),
    (
        "cpu",
        &[
            "M6 6h8v8H6z",
            "M8.5 8.5h3v3h-3z",
            "M8 3.5V6M12 3.5V6M8 14v2.5M12 14v2.5M3.5 8H6M3.5 12H6M14 8h2.5M14 12h2.5",
        ],
    ),
    (
        "globe",
        &[
            "M10 10m-6.5 0a6.5 6.5 0 1 0 13 0a6.5 6.5 0 1 0-13 0",
            "M3.5 10h13",
            "M10 3.5c2 2 2.8 4.2 2.8 6.5s-.8 4.5-2.8 6.5c-2-2-2.8-4.2-2.8-6.5s.8-4.5 2.8-6.5z",
        ],
    ),
    ("activity", &["M3 10.5h3l2-5 4 9 2-4h3"]),
    (
        "eye",
        &[
            "M2.5 10s2.8-5 7.5-5 7.5 5 7.5 5-2.8 5-7.5 5-7.5-5-7.5-5z",
            "M10 10m-2.2 0a2.2 2.2 0 1 0 4.4 0a2.2 2.2 0 1 0-4.4 0",
        ],
    ),
    ("bell", &["M5.5 13.5V9a4.5 4.5 0 0 1 9 0v4.5l1.3 1.5H4.2z", "M8.4 16.8a1.8 1.8 0 0 0 3.2 0"]),
];

/// Filled icons, as complete SVG bodies (24 × 24 view box).
/// "gear": Material Symbols "settings" (Apache-2.0, Google), the Android settings icon.
const FILLED: &[(&str, &str)] = &[(
    "gear",
    "<path fill-rule=\"evenodd\" d=\"M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.49.49 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.48.48 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 0 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32a.49.49 0 0 0-.12-.61l-2.01-1.58zM12 15.6a3.6 3.6 0 1 1 0-7.2 3.6 3.6 0 0 1 0 7.2z\"/>",
)];

pub fn svg_for(name: &str) -> Option<String> {
    if let Some((_, body)) = FILLED.iter().find(|(n, _)| *n == name) {
        return Some(format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\" fill=\"#000\">{body}</svg>"));
    }
    // "thumb-down", "thumb-mid": the thumb turned.
    let (base, turn) = match name {
        "thumb-down" => ("thumb", 180),
        "thumb-mid" => ("thumb", -90),
        n => (n, 0),
    };
    let name = base;
    let (_, paths) = ICONS.iter().find(|(n, _)| *n == name)?;
    let body: String = paths.iter().map(|d| format!("<path d=\"{d}\"/>")).collect();
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 20 20\" width=\"20\" height=\"20\" fill=\"none\" \
         stroke=\"#000\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><g transform=\"rotate({turn} 10 10)\">{body}</g></svg>"
    ))
}

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        let name = path.strip_prefix("icons/").and_then(|p| p.strip_suffix(".svg"));
        Ok(name.and_then(svg_for).map(|s| Cow::Owned(s.into_bytes())))
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        Ok(if path.starts_with("icons") {
            ICONS.iter().map(|(n, _)| format!("icons/{n}.svg").into()).collect()
        } else {
            vec![]
        })
    }
}
