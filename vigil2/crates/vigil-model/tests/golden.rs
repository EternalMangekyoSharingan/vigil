//! Vigil 2 must agree with Vigil 1. The expected values in
//! `vigil2/tests/golden/model.json` were computed by the Python code from SYNTHETIC
//! inputs (see make_golden.py next to it).

use serde_json::Value;
use std::path::PathBuf;
use vigil_model::fixes::{self, Risk};
use vigil_model::{attack, commands, distro, finding, wording, Builder};

fn golden() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/model.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("golden file")).expect("golden json")
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// JSON equality where 1 and 1.0 are the same number (Python writes `when=1` as 1).
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

fn s(v: &Value) -> Option<&str> {
    v.as_str()
}

#[test]
fn title_problems() {
    let g = golden();
    let mut bad = vec![];
    for (title, want) in g["title_problems"].as_object().unwrap() {
        let got = serde_json::to_value(wording::title_problems(title)).unwrap();
        if &got != want {
            bad.push(format!("{title:?}: rust {got} python {want}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn one_sentence() {
    let g = golden();
    let bad: Vec<_> = g["one_sentence"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(t, want)| wording::one_sentence(t) != want.as_bool().unwrap())
        .map(|(t, want)| format!("{t:?}: python says {want}"))
        .collect();
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn fit_title_and_numbers() {
    let g = golden();
    for case in g["fit_title"].as_array().unwrap() {
        let cands: Vec<String> = case["in"].as_array().unwrap().iter().map(|c| c.as_str().unwrap_or("").to_string()).collect();
        assert_eq!(wording::fit_title(&cands, wording::TITLE_MAX), case["out"].as_str().unwrap(), "{cands:?}");
    }
    for (secs, want) in g["every"].as_object().unwrap() {
        assert_eq!(wording::every(secs.parse().unwrap()), want.as_str().unwrap(), "every({secs})");
    }
    for (secs, want) in g["span"].as_object().unwrap() {
        let n: f64 = secs.parse().unwrap();
        assert_eq!(wording::span(n, false), want[0].as_str().unwrap(), "span({secs})");
        assert_eq!(wording::span(n, true), want[1].as_str().unwrap(), "span({secs}, short)");
    }
    for pair in g["kb"].as_array().unwrap() {
        assert_eq!(wording::kb(pair[0].as_f64().unwrap()), pair[1].as_str().unwrap(), "kb({})", pair[0]);
    }
}

#[test]
fn names() {
    let g = golden();
    for case in g["friendly_program"].as_array().unwrap() {
        let a = &case["in"];
        let got = wording::friendly_program(s(&a[0]), s(&a[1]), s(&a[2]));
        assert_eq!(got, case["out"].as_str().unwrap(), "{a}");
    }
    for pair in g["owner_name"].as_array().unwrap() {
        assert_eq!(wording::owner_name(s(&pair[0])).as_deref(), s(&pair[1]), "owner_name({})", pair[0]);
    }
    for (host, want) in g["short_host"].as_object().unwrap() {
        assert_eq!(wording::short_host(host), want.as_str().unwrap());
    }
}

#[test]
fn tokens() {
    let g = golden();
    let mut bad = vec![];
    for (cmd, want) in g["tokenize"].as_object().unwrap() {
        let got = serde_json::to_value(commands::tokenize(cmd)).unwrap();
        if &got != want {
            bad.push(format!("{cmd:?}\n  rust   {got}\n  python {want}"));
        }
    }
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), g["tokenize"].as_object().unwrap().len(), bad.join("\n"));
    assert_eq!(serde_json::to_value(commands::LEGEND).unwrap(), g["legend"]);
}

#[test]
fn ids_and_attack() {
    let g = golden();
    for row in g["finding_id"].as_array().unwrap() {
        let got = finding::finding_id(s(&row[0]).unwrap(), s(&row[1]).unwrap(), s(&row[2]).unwrap());
        assert_eq!(got, row[3].as_str().unwrap());
    }
    for (key, want) in g["attack_by_check"].as_object().unwrap() {
        let (tool, check) = key.split_once('/').unwrap();
        assert_eq!(&serde_json::to_value(attack::for_check(tool, check)).unwrap(), want, "{key}");
    }
    for row in g["attack_persist"].as_array().unwrap() {
        let got = attack::for_persist(s(&row[0]).unwrap(), s(&row[1]).unwrap(), s(&row[2]).unwrap());
        assert_eq!(serde_json::to_value(got).unwrap(), row[3]);
    }
    assert_eq!(attack::TECHNIQUES.len(), g["techniques"].as_object().unwrap().len());
    assert_eq!(serde_json::to_value(attack::TACTICS).unwrap(), g["tactics"]);
}

#[test]
fn distros_and_owner_checks() {
    let g = golden();
    for (name, want) in g["os_release"].as_object().unwrap() {
        let osr = distro::os_release(&root().join("tests/fixtures/os-release").join(name));
        assert_eq!(serde_json::to_value(&osr).unwrap(), want[0], "{name}");
        assert_eq!(distro::family(&osr), s(&want[1]), "{name}");
    }
    for (name, want) in g["owner_check"].as_object().unwrap() {
        let osr = distro::os_release(&root().join("tests/fixtures/os-release").join(name));
        let got = serde_json::to_value(fixes::owner_check("/usr/bin/x", distro::family(&osr))).unwrap();
        assert!(same(&got, want), "{name}\n  rust   {got}\n  python {want}");
    }
}

fn risk(r: &str) -> Risk {
    serde_json::from_value(Value::String(r.into())).unwrap()
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

fn opt(o: &Value) -> fixes::FixOption {
    fixes::option(o["title"].as_str().unwrap(), o["what"].as_str().unwrap(), risk(o["risk"].as_str().unwrap()), &strs(&o["commands"]), &strs(&o["undo"]))
        .with_steps(&strs(&o["steps"]), &strs(&o["undo_steps"]))
}

/// The same call Vigil 1's make_golden.py made, through the Rust builder.
fn build(a: &Value) -> Result<finding::Finding, finding::FindingError> {
    let mut b = Builder::new(s(&a["tool"]).unwrap(), s(&a["check"]).unwrap(), s(&a["title"]).unwrap(), s(&a["summary"]).unwrap(), s(&a["severity"]).unwrap());
    for sig in a["signals"].as_array().into_iter().flatten() {
        b = match s(&sig[2]) {
            Some(k) => b.signal_kind(s(&sig[0]).unwrap(), sig[1].as_f64().unwrap(), k),
            None => b.signal(s(&sig[0]).unwrap(), sig[1].as_f64().unwrap()),
        };
    }
    if let Some(l) = s(&a["likely"]) {
        b = b.likely(l);
    }
    if let Some(c) = s(&a["confidence"]) {
        b = b.confidence(c, s(&a["confidence_reason"]).unwrap_or(""));
    }
    if let Some(x) = s(&a["subject"]) {
        b = b.subject(x);
    }
    if let Some(x) = s(&a["data"]) {
        b = b.data(x);
    }
    b = b.when(a["when"].as_f64().unwrap());
    for t in strs(&a["tags"]) {
        b = b.tag(t);
    }
    if a["attack"].is_array() {
        b = b.attack_ids(&strs(&a["attack"]));
    }
    for e in a["evidence"].as_array().into_iter().flatten() {
        b = b.evidence_raw(e.clone());
    }
    for i in a["iocs"].as_array().into_iter().flatten() {
        b = b.ioc_raw(i.clone());
    }
    for t in a["technical"].as_array().into_iter().flatten() {
        b = b.technical_raw(t.clone());
    }
    if let Some(fx) = a.get("fixes") {
        let osr = distro::os_release(&root().join("tests/fixtures/os-release").join(s(&fx["osr"]).unwrap()));
        let check = fx["check"].as_array().into_iter().flatten().map(opt).collect();
        let fix = fx["fix"].as_array().into_iter().flatten().map(opt).collect();
        b = b.fixes(fixes::panel(&osr, check, fix, None));
    }
    b.make()
}

#[test]
fn findings_match_vigil_1() {
    let g = golden();
    for case in g["make"].as_array().unwrap() {
        let f = build(&case["args"]).unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        let got = f.to_value();
        assert!(same(&got, &case["out"]), "{}\n  rust   {got}\n  python {}", case["name"], case["out"]);
        assert!(f.problems().is_empty());
    }
    for case in g["broken"].as_array().unwrap() {
        let err = build(&case["args"]).expect_err(case["name"].as_str().unwrap());
        assert_eq!(err.to_string(), case["error"].as_str().unwrap());
    }
}

#[test]
fn jsonl_round_trip_and_bad_lines() {
    let g = golden();
    let fs: Vec<_> = g["make"].as_array().unwrap().iter().map(|c| build(&c["args"]).unwrap()).collect();
    let text = finding::to_jsonl(&fs);
    let extra = "not json\n{\"title\": \"x\"}\n";
    let (back, skipped) = finding::from_jsonl(&(text.clone() + extra), false).unwrap();
    assert_eq!(back, fs);
    assert_eq!(skipped.iter().map(|(n, _)| *n).collect::<Vec<_>>(), [fs.len() + 1, fs.len() + 2]);
    assert!(finding::from_jsonl("{\"title\": \"x\"}", true).is_err());
    // Byte for byte what Python's json.dumps(sort_keys=True, ensure_ascii=False) writes,
    // for findings whose numbers Python also writes as floats.
    let first = &g["make"][0]["out"];
    let python_line = python_dumps(first);
    assert_eq!(text.lines().next().unwrap(), python_line);
}

/// What Python's json.dumps(v, sort_keys=True, ensure_ascii=False) gives for a value
/// whose numbers are all written the same way by both languages.
fn python_dumps(v: &Value) -> String {
    vigil_model::pyjson::dumps(v)
}

#[test]
fn worst_and_sort() {
    let g = golden();
    let mut fs: Vec<_> = [2usize, 0].iter().map(|i| build(&g["make"][*i]["args"]).unwrap()).collect();
    assert_eq!(finding::worst(&fs), Some(vigil_model::Severity::High));
    finding::sort(&mut fs);
    assert_eq!(fs.iter().map(|f| f.severity.as_str()).collect::<Vec<_>>(), ["High", "Low"]);
    assert_eq!(finding::worst(&[]), None);
}
