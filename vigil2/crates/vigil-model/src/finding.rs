//! The one finding format every part of Vigil produces and Cases imports.
//!
//! Port of Vigil 1's `vigil/core/finding.py`, field for field, so findings written by
//! either version can be read by the other. A finding:
//!
//! | field | meaning |
//! | --- | --- |
//! | `id` | stable id: the same tool, check and subject give the same id |
//! | `tool` | "pkg", "files", "persist", "tasks", "net", ... |
//! | `check` | which check raised it (machine name) |
//! | `title` | plain English, at most 60 characters ([`crate::wording`] rules) |
//! | `summary` | one sentence |
//! | `severity` | High / Medium / Low / Info |
//! | `signals` | what was noticed, strongest first, each with a strength 0..1 |
//! | `likely` | the likely explanation (one or two sentences), or none |
//! | `confidence` | High / Medium / Low, and why |
//! | `fixes` | a [`FixPanel`]: Check / Fix / Undo commands, or none |
//! | `evidence` | file and line, path, pid, hash ... |
//! | `iocs` | indicators worth exporting (urls, domains, ips, hashes) |
//! | `technical` | raw details, shown collapsed |
//! | `subject` | what the finding is about (a path, package, pid ...) |
//! | `source` | which tool, which check, which data, when |
//! | `tags` | free-form short labels |
//! | `attack` | MITRE ATT&CK techniques this is evidence of |
//! | `format` | [`FORMAT_VERSION`] |
//!
//! [`Builder::make`] validates as it builds, so no check can emit a finding that breaks
//! the rules. Imported findings are validated with [`problems`] before they are trusted.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fmt;

use crate::attack::{self, AttackTag};
use crate::fixes::FixPanel;
use crate::pyjson::{self, truthy};
use crate::{sha1, wording};

pub const FORMAT_VERSION: u32 = 1;
pub const SEVERITIES: [&str; 4] = ["High", "Medium", "Low", "Info"];
pub const CONFIDENCE: [&str; 3] = ["High", "Medium", "Low"];
pub const IOC_TYPES: [&str; 9] = ["ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "file"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    /// Info 0 .. High 3.
    pub fn rank(self) -> u8 {
        self as u8
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        [Severity::High, Severity::Medium, Severity::Low, Severity::Info].into_iter().find(|v| v.as_str() == s)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    pub text: String,
    pub strength: f64,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInfo {
    pub level: Confidence,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ioc {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Technical {
    pub label: String,
    #[serde(default)]
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    pub tool: String,
    pub check: String,
    #[serde(default)]
    pub data: Value,
    pub when: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub format: u32,
    pub id: String,
    pub tool: String,
    pub check: String,
    pub title: String,
    pub summary: String,
    pub severity: Severity,
    pub signals: Vec<Signal>,
    #[serde(default)]
    pub likely: Option<String>,
    pub confidence: ConfidenceInfo,
    #[serde(default)]
    pub fixes: Option<FixPanel>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub iocs: Vec<Ioc>,
    #[serde(default)]
    pub technical: Vec<Technical>,
    #[serde(default)]
    pub subject: String,
    pub source: Source,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attack: Vec<AttackTag>,
    /// Keys this version does not know (kept so imported findings round-trip).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct FindingError(pub String);

/// The stable id: the same tool, check and subject always give the same id.
pub fn finding_id(tool: &str, check: &str, subject: &str) -> String {
    sha1::hex(format!("{tool}|{check}|{subject}").as_bytes())[..16].to_string()
}

/// Python's `round(x, 2)`: the nearest of the two-decimal values, ties to even.
pub fn round_to(x: f64, places: usize) -> f64 {
    format!("{x:.places$}").parse().unwrap_or(x)
}

/// A signal with its strength clamped to 0..1 and rounded to two places.
pub fn signal(text: &str, strength: f64, kind: Option<&str>) -> Signal {
    Signal { text: text.into(), strength: round_to(strength.clamp(0.0, 1.0), 2), kind: kind.map(String::from) }
}

/// One raw scored observation (the building block of the Network and Files scores).
/// `means` says, in plain words, what it would do to you; `stats` holds the numbers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scored {
    pub check: String,
    pub points: f64,
    pub reason: String,
    pub data: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub means: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<Value>,
}

pub fn scored(check: &str, points: f64, reason: &str, data: Value, means: Option<&str>, stats: Option<Value>) -> Scored {
    Scored {
        check: check.into(),
        points: round_to(points, 1),
        reason: reason.into(),
        data,
        means: means.filter(|m| !m.is_empty()).map(String::from),
        stats: stats.filter(truthy),
    }
}

/// Builds one finding. Every field but the five in [`Builder::new`] is optional.
#[derive(Debug, Clone)]
pub struct Builder {
    tool: String,
    check: String,
    title: String,
    summary: String,
    severity: String,
    signals: Vec<Signal>,
    likely: Option<String>,
    confidence: String,
    confidence_reason: String,
    subject: String,
    fixes: Option<FixPanel>,
    evidence: Vec<Value>,
    iocs: Vec<Value>,
    technical: Vec<Value>,
    data: Value,
    when: Option<f64>,
    tags: Vec<String>,
    attack: Option<Vec<AttackTag>>,
}

impl Builder {
    pub fn new(tool: &str, check: &str, title: &str, summary: &str, severity: &str) -> Self {
        Builder {
            tool: tool.into(),
            check: check.into(),
            title: title.into(),
            summary: summary.into(),
            severity: severity.into(),
            signals: vec![],
            likely: None,
            confidence: "Medium".into(),
            confidence_reason: String::new(),
            subject: String::new(),
            fixes: None,
            evidence: vec![],
            iocs: vec![],
            technical: vec![],
            data: Value::String(String::new()),
            when: None,
            tags: vec![],
            attack: None,
        }
    }
    pub fn signal(mut self, text: &str, strength: f64) -> Self {
        self.signals.push(signal(text, strength, None));
        self
    }
    pub fn signal_kind(mut self, text: &str, strength: f64, kind: &str) -> Self {
        self.signals.push(signal(text, strength, Some(kind)));
        self
    }
    /// A signal kept exactly as given (Vigil 1's "already a dict" case).
    pub fn raw_signal(mut self, s: Signal) -> Self {
        self.signals.push(s);
        self
    }
    pub fn likely(mut self, text: &str) -> Self {
        self.likely = Some(text.into());
        self
    }
    pub fn confidence(mut self, level: &str, reason: &str) -> Self {
        self.confidence = level.into();
        self.confidence_reason = reason.into();
        self
    }
    pub fn subject(mut self, subject: &str) -> Self {
        self.subject = subject.into();
        self
    }
    pub fn fixes(mut self, panel: FixPanel) -> Self {
        self.fixes = Some(panel);
        self
    }
    pub fn evidence(mut self, kind: &str, value: impl Into<Value>, note: Option<&str>) -> Self {
        let mut e = json!({"kind": kind, "value": value.into()});
        if let Some(n) = note {
            e["note"] = n.into();
        }
        self.evidence.push(e);
        self
    }
    pub fn evidence_raw(mut self, e: Value) -> Self {
        self.evidence.push(e);
        self
    }
    pub fn ioc(mut self, kind: &str, value: &str) -> Self {
        self.iocs.push(json!({"type": kind, "value": value}));
        self
    }
    pub fn ioc_raw(mut self, i: Value) -> Self {
        self.iocs.push(i);
        self
    }
    pub fn technical(mut self, label: &str, value: impl Into<Value>) -> Self {
        self.technical.push(json!({"label": label, "value": value.into()}));
        self
    }
    pub fn technical_raw(mut self, t: Value) -> Self {
        self.technical.push(t);
        self
    }
    /// Which data the check read ("PKGBUILD line 12", "/proc/4410/maps").
    pub fn data(mut self, data: impl Into<Value>) -> Self {
        self.data = data.into();
        self
    }
    /// When it was seen (seconds since the epoch); now when not given.
    pub fn when(mut self, when: f64) -> Self {
        self.when = Some(when);
        self
    }
    pub fn tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.into());
        self
    }
    /// ATT&CK techniques by id, instead of the default mapping for this check.
    pub fn attack_ids(mut self, ids: &[&str]) -> Self {
        self.attack = Some(ids.iter().map(|id| attack::tag(id)).collect());
        self
    }
    pub fn attack_tags(mut self, tags: Vec<AttackTag>) -> Self {
        self.attack = Some(tags);
        self
    }

    /// The finding as Vigil 1 would write it, before validation.
    fn to_value(&self) -> Value {
        let when = self.when.unwrap_or_else(now);
        let mut signals = self.signals.clone();
        signals.sort_by(|a, b| b.strength.partial_cmp(&a.strength).unwrap_or(std::cmp::Ordering::Equal));
        let attack = self.attack.clone().unwrap_or_else(|| attack::for_check(&self.tool, &self.check));
        json!({
            "format": FORMAT_VERSION, "id": finding_id(&self.tool, &self.check, &self.subject),
            "tool": self.tool, "check": self.check, "title": self.title, "summary": self.summary,
            "severity": self.severity, "signals": signals, "likely": self.likely,
            "confidence": {"level": self.confidence, "reason": self.confidence_reason},
            "fixes": self.fixes, "evidence": self.evidence, "iocs": self.iocs, "technical": self.technical,
            "subject": self.subject,
            "source": {"tool": self.tool, "check": self.check, "data": self.data, "when": when},
            "tags": self.tags, "attack": attack,
        })
    }

    /// Build and validate. The error lists every rule the finding breaks.
    pub fn make(self) -> Result<Finding, FindingError> {
        let v = self.to_value();
        let bad = problems(&v);
        if !bad.is_empty() {
            return Err(FindingError(format!("{}/{}: {}", self.tool, self.check, bad.join("; "))));
        }
        serde_json::from_value(v).map_err(|e| FindingError(format!("{}/{}: {e}", self.tool, self.check)))
    }
}

pub fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

const REQUIRED: [&str; 9] = ["id", "tool", "check", "title", "summary", "severity", "signals", "confidence", "source"];

/// Every way `f` (a finding as JSON) breaks the suite's finding rules (empty when fine).
pub fn problems(f: &Value) -> Vec<String> {
    let mut out: Vec<String> = REQUIRED.iter().filter(|k| f.get(**k).is_none()).map(|k| format!("missing {k}")).collect();
    if !out.is_empty() {
        return out;
    }
    let s = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("");
    out.extend(wording::title_problems(s("title")).into_iter().map(|p| format!("title {p}")));
    if !wording::one_sentence(s("summary")) {
        out.push("summary must be exactly one sentence".into());
    }
    if !SEVERITIES.contains(&s("severity")) || !f["severity"].is_string() {
        out.push("severity must be one of ('High', 'Medium', 'Low', 'Info')".into());
    }
    let level = f["confidence"].get("level").and_then(Value::as_str);
    if !level.is_some_and(|l| CONFIDENCE.contains(&l)) {
        out.push("confidence must be one of ('High', 'Medium', 'Low')".into());
    }
    let signals = f["signals"].as_array().cloned().unwrap_or_default();
    for sig in &signals {
        let text_ok = sig.get("text").is_some_and(truthy);
        let strength_ok = sig.get("strength").and_then(Value::as_f64).is_some_and(|x| (0.0..=1.0).contains(&x));
        if !text_ok || !strength_ok {
            out.push("every signal needs text and a strength between 0 and 1".into());
            break;
        }
    }
    if matches!(s("severity"), "High" | "Medium") && signals.is_empty() {
        out.push("a High or Medium finding must say what was noticed (signals)".into());
    }
    for i in f.get("iocs").and_then(Value::as_array).into_iter().flatten() {
        let kind_ok = i.get("type").and_then(Value::as_str).is_some_and(|t| IOC_TYPES.contains(&t));
        if !kind_ok || !i.get("value").is_some_and(truthy) {
            out.push(format!("bad indicator {}", pyjson::repr(i)));
        }
    }
    let fix_opts = f.get("fixes").and_then(|x| x.get("fix")).and_then(Value::as_array);
    for opt in fix_opts.into_iter().flatten() {
        let has = |k: &str| opt.get(k).is_some_and(truthy);
        if has("commands") && !(has("undo") || has("undo_steps")) {
            let title = match opt.get("title") {
                Some(Value::String(t)) => t.clone(),
                Some(v) if !v.is_null() => v.to_string(),
                _ => "None".into(),
            };
            out.push(format!("fix '{title}' has no undo"));
        }
    }
    for a in f.get("attack").and_then(Value::as_array).into_iter().flatten() {
        let id = a.get("id");
        if !id.and_then(Value::as_str).is_some_and(attack::valid_id) {
            out.push(format!("bad ATT&CK id {}", id.map_or("None".into(), pyjson::repr)));
        }
    }
    let src = &f["source"];
    if !(src.get("tool").is_some_and(truthy) && src.get("check").is_some_and(truthy) && src.get("when").is_some_and(truthy))
    {
        out.push("source must say which tool, which check and when".into());
    }
    out
}

impl Finding {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
    pub fn problems(&self) -> Vec<String> {
        problems(&self.to_value())
    }
}

/// The highest severity among `findings`, or None.
pub fn worst(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

/// Most severe first, then by title.
pub fn sort(findings: &mut [Finding]) {
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.title.cmp(&b.title)));
}

/// The shared export: JSON lines, one finding per line, as Vigil 1 writes them.
pub fn to_jsonl(findings: &[Finding]) -> String {
    findings.iter().map(|f| pyjson::dumps(f) + "\n").collect()
}

/// Parse JSON lines. Lines that are not valid findings are skipped and reported as
/// (line number, reason); with `strict` the first bad line is an error instead.
/// Findings that parsed, and (line number, reason) for every line that did not.
pub type Imported = (Vec<Finding>, Vec<(usize, String)>);

pub fn from_jsonl(text: &str, strict: bool) -> Result<Imported, FindingError> {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for (n, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)) {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            skipped.push((n, "not JSON".to_string()));
            continue;
        };
        let bad = if v.is_object() { problems(&v) } else { vec!["not an object".into()] };
        let parsed = if bad.is_empty() { serde_json::from_value::<Finding>(v).map_err(|e| vec![e.to_string()]) } else { Err(bad) };
        match parsed {
            Ok(f) => out.push(f),
            Err(bad) if strict => return Err(FindingError(format!("line {n}: {}", bad.join("; ")))),
            Err(bad) => skipped.push((n, bad.join("; "))),
        }
    }
    Ok((out, skipped))
}
