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
        &["M5 3.5h6.5L15 7v9.5H5z", "M11.5 3.5V7H15", "M10 9.6l2.4 1v1.8c0 1.4-1 2.4-2.4 2.9-1.4-.5-2.4-1.5-2.4-2.9v-1.8z"],
    ),
    ("software", &["M10 3.5l6 3v7l-6 3-6-3v-7z", "M4 6.5l6 3 6-3", "M10 9.5v7", "M7 5l6 3"]),
    ("guard", &["M10 3.5l5.5 2v4.2c0 3.3-2.3 5.6-5.5 6.8-3.2-1.2-5.5-3.5-5.5-6.8V5.5z", "M7.6 10.2l1.7 1.7 3.2-3.4"]),
    ("canaries", &["M5.5 13c0-3 2.2-5.5 5-5.5H13l2.5-1.5v3l-2 1c0 2.8-2.3 4.5-5 4.5z", "M5.5 13 3.5 15.5", "M12.3 9.6h.01"]),
    ("cases", &["M4 4.5v11", "M4 6.5h9", "M7 10h8", "M5.5 13.5h7"]),
    (
        "gear",
        &[
            "M10 10m-2.3 0a2.3 2.3 0 1 0 4.6 0a2.3 2.3 0 1 0-4.6 0",
            "M10 2.8l1.3 1.9 2.2-.6.5 2.2 2.2.6-.6 2.2L17.2 10l-1.6 1.6.6 2.2-2.2.6-.5 2.2-2.2-.6L10 17.2l-1.3-1.9-2.2.6-.5-2.2-2.2-.6.6-2.2L2.8 10l1.6-1.6-.6-2.2 2.2-.6.5-2.2 2.2.6z",
        ],
    ),
    ("search", &["M8.8 8.8m-4.8 0a4.8 4.8 0 1 0 9.6 0a4.8 4.8 0 1 0-9.6 0", "M12.4 12.4 16 16"]),
    ("keys", &["M3 6h14v8.5H3z", "M5.5 8.5h.01M8.5 8.5h.01M11.5 8.5h.01M14.5 8.5h.01M6.5 12h7"]),
    ("close", &["M5 5l10 10M15 5 5 15"]),
];

pub fn svg_for(name: &str) -> Option<String> {
    let (_, paths) = ICONS.iter().find(|(n, _)| *n == name)?;
    let body: String = paths.iter().map(|d| format!("<path d=\"{d}\"/>")).collect();
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 20 20\" width=\"20\" height=\"20\" fill=\"none\" \
         stroke=\"#000\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\">{body}</svg>"
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
