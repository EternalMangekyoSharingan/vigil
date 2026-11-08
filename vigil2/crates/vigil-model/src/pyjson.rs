//! JSON text exactly as Vigil 1 writes it, so files can be compared byte for byte.
//!
//! `json.dumps(obj, sort_keys=True, ensure_ascii=False)` separates items with ", " and
//! keys from values with ": ". serde_json's `Value` keeps object keys sorted already, so
//! only the separators differ. Also Python's `repr()` of a JSON value, which Vigil 1
//! puts in some error messages.

use serde::Serialize;
use serde_json::ser::{Formatter, Serializer};
use serde_json::Value;
use std::io;

struct PyFormatter;

impl Formatter for PyFormatter {
    fn begin_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            w.write_all(b", ")
        }
    }
    fn begin_object_key<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            w.write_all(b", ")
        }
    }
    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }
}

/// The same value with every object's keys in sorted order. serde_json keeps keys
/// sorted only while no crate in the build enables its `preserve_order` feature (the
/// UI toolkit does), so the order is made explicit here.
pub fn sorted(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(String, Value)> = m.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// `json.dumps(value, sort_keys=True, ensure_ascii=False)`.
pub fn dumps<T: Serialize>(value: &T) -> String {
    let v = sorted(serde_json::to_value(value).unwrap_or(Value::Null));
    let mut out = Vec::new();
    let mut ser = Serializer::with_formatter(&mut out, PyFormatter);
    if v.serialize(&mut ser).is_err() {
        return "null".into();
    }
    String::from_utf8(out).unwrap_or_default()
}

fn repr_str(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::from(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// Python's `repr()` of a value parsed from JSON (keys in sorted order).
pub fn repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => repr_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(m) => {
            let mut m: Vec<(&String, &Value)> = m.iter().collect();
            m.sort_by(|a, b| a.0.cmp(b.0));
            format!(
                "{{{}}}",
                m.iter().map(|(k, v)| format!("{}: {}", repr_str(k), repr(v))).collect::<Vec<_>>().join(", ")
            )
        }
    }
}

/// Python truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}
