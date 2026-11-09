//! The process checks must agree with Vigil 1 on tests/golden/tasks.json (SYNTHETIC inputs:
//! the /proc fixture and hand-made processes). Regenerate with tests/golden/make_golden.py.

use std::collections::HashMap;
use vigil_engine::{secrets, tasks};

fn golden() -> serde_json::Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/tasks.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("tasks.json")).expect("json")
}

fn check(set: &serde_json::Value, home: &str) -> usize {
    let procs: HashMap<u32, tasks::ProcFacts> = set["procs"]
        .as_object()
        .expect("procs")
        .iter()
        .map(|(k, v)| (k.parse().expect("pid"), serde_json::from_value(v.clone()).expect("facts")))
        .collect();
    let mut n = 0;
    for (pid, want) in set["flags"].as_object().expect("flags") {
        let p = &procs[&pid.parse::<u32>().expect("pid")];
        let got: Vec<serde_json::Value> = tasks::flags(p, &procs, home)
            .into_iter()
            .map(|f| serde_json::json!([f.check, f.severity, f.strength, f.text]))
            .collect();
        assert_eq!(&serde_json::Value::Array(got), want, "pid {pid}");
        n += want.as_array().map_or(0, Vec::len);
    }
    n
}

#[test]
fn process_checks_match_vigil_1() {
    let g = golden();
    let home = g["home"].as_str().expect("home");
    let a = check(&g["fixture"], home);
    let b = check(&g["cases"], home);
    assert_eq!((a, b), (2, 23), "flags in the fixture and the cases");
}

#[test]
fn secret_paths_match_vigil_1() {
    let g = golden();
    for (path, want) in g["classify"].as_object().expect("classify") {
        assert_eq!(secrets::classify(path), want.as_str(), "{path}");
    }
}

/// Every flag becomes a valid finding (titles fit, one-sentence summary, known ATT&CK ids).
#[test]
fn every_flag_makes_a_valid_finding() {
    let g = golden();
    let set = &g["cases"];
    let procs: HashMap<u32, tasks::ProcFacts> = set["procs"]
        .as_object()
        .expect("procs")
        .iter()
        .map(|(k, v)| (k.parse().expect("pid"), serde_json::from_value(v.clone()).expect("facts")))
        .collect();
    let osr = vigil_model::distro::parse_os_release("ID=arch\nNAME=\"Arch Linux\"\n");
    let mut n = 0;
    for p in procs.values() {
        for f in tasks::flags(p, &procs, "/home/alice") {
            let cx = tasks::Context {
                user: "alice",
                started: Some(1000.0),
                chain: vec![p.name.clone(), "systemd".into()],
                viewer_uid: 1000,
                uid: 1000,
                osr: &osr,
                now: 2000.0,
            };
            let made = tasks::finding(p, &procs, &f, &cx).unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(made.severity.as_str(), f.severity);
            assert!(made.title.chars().count() <= 60, "{}", made.title);
            n += 1;
        }
    }
    assert_eq!(n, 23);
}
