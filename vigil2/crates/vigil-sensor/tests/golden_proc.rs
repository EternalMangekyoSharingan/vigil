//! The /proc source must agree with Vigil 1's collector on the SYNTHETIC fixture
//! (tests/fixtures/proc). Expected values: vigil2/tests/golden/proc.json.

use serde_json::Value;
use std::path::PathBuf;
use vigil_sensor::procfs::{self, ProcRoot};

fn here() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn golden() -> Value {
    serde_json::from_str(&std::fs::read_to_string(here().join("../../tests/golden/proc.json")).unwrap()).unwrap()
}

/// The same made-up names make_golden.py uses, so the file is the same on every machine.
fn names(uid: u32) -> String {
    if uid == 0 {
        "root".into()
    } else {
        format!("user-{uid}")
    }
}

fn fixture(tag: &str) -> (PathBuf, std::collections::HashSet<u32>) {
    let dst = std::env::temp_dir().join(format!("vigil-proc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dst);
    let blocked = procfs::materialise_fixture(&here().join("../../../tests/fixtures/proc"), &dst).unwrap();
    (dst, blocked)
}

fn same(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) if (x.as_f64().unwrap() - y.as_f64().unwrap()).abs() < 1e-6 => {}
        (Value::Object(x), Value::Object(y)) => {
            for k in x.keys().chain(y.keys()).collect::<std::collections::BTreeSet<_>>() {
                same(x.get(k).unwrap_or(&Value::Null), y.get(k).unwrap_or(&Value::Null), &format!("{path}.{k}"), out);
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                same(p, q, &format!("{path}[{i}]"), out);
            }
        }
        _ if a == b => {}
        _ => out.push(format!("{path}: rust {a} python {b}")),
    }
}

fn check(viewer: u32, simulate_non_root: bool, key: &str) {
    let (dir, blocked) = fixture(key);
    let mut root = ProcRoot::at(&dir);
    root.user_name = names;
    if simulate_non_root {
        root.blocked = blocked;
    }
    let snap = root.net_snapshot(1000.0, viewer);
    let mut got = serde_json::to_value(&snap).unwrap();
    for k in ["taken_at", "byte_counts", "hidepid"] {
        got.as_object_mut().unwrap().remove(k);
    }
    let mut diffs = vec![];
    same(&got, &golden()[key], key, &mut diffs);
    std::fs::remove_dir_all(dir).unwrap();
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
}

#[test]
fn snapshot_as_root_matches_vigil_1() {
    check(0, false, "root");
}

#[test]
fn snapshot_as_a_normal_user_matches_vigil_1() {
    check(1000, true, "user1000");
}

#[test]
fn helpers_match_vigil_1() {
    let g = golden();
    for row in g["program_identity"].as_array().unwrap() {
        let cmd: Vec<String> = row[1].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
        let (k, n) = procfs::program_identity(row[0].as_str(), &cmd, row[2].as_str().unwrap());
        assert_eq!(serde_json::json!([k, n]), row[3], "{row}");
    }
    for row in g["decode_address"].as_array().unwrap() {
        let (ip, port) = procfs::decode_address(row[0].as_str().unwrap(), true).unwrap();
        assert_eq!(serde_json::json!([ip, port]), row[1], "{row}");
    }
    for bad in g["decode_address_bad"].as_array().unwrap() {
        assert!(procfs::decode_address(bad.as_str().unwrap(), true).is_none(), "{bad}");
    }
    for (ip, scope) in g["scope_of"].as_object().unwrap() {
        assert_eq!(procfs::scope_of(ip), scope.as_str().unwrap(), "{ip}");
    }
}

#[test]
fn every_process_is_listed_and_the_live_system_reads() {
    let (dir, _) = fixture("list");
    let mut root = ProcRoot::at(&dir);
    root.user_name = names;
    let list = root.process_list(1.0, 0);
    assert_eq!(list.processes.len(), 13);
    let crafted = list.processes.iter().find(|p| p.comm.contains(')')).expect("the crafted comm");
    assert!(crafted.started.is_some(), "a ')' in the name must not break stat parsing");
    std::fs::remove_dir_all(dir).unwrap();
    // CLAUDE.md: run the real collector once and confirm it reads live data.
    let live = ProcRoot::system();
    let list = live.process_list(1.0, nix::unistd::getuid().as_raw());
    assert!(list.processes.iter().any(|p| p.pid == std::process::id()), "sees itself");
    let snap = live.net_snapshot(1.0, nix::unistd::getuid().as_raw());
    assert!(snap.pids_visible > 0);
}
