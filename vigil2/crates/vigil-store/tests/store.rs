//! The store on SYNTHETIC data: the /proc fixture (tests/fixtures/proc) and findings
//! built here.

use std::path::PathBuf;
use vigil_model::Builder;
use vigil_sensor::procfs::{materialise_fixture, ProcRoot};
use vigil_store::{Event, Store, StoreError, SCHEMA_VERSION};

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vigil-store-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn fixture_root(tag: &str) -> (PathBuf, ProcRoot) {
    let d = tmp(tag);
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/proc");
    materialise_fixture(&src, &d.join("proc")).unwrap();
    let r = ProcRoot::at(d.join("proc"));
    (d, r)
}

#[test]
fn creates_migrates_and_refuses_newer_files() {
    let d = tmp("schema");
    let p = d.join("vigil.db");
    let s = Store::open(&p).unwrap();
    assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    drop(s);
    // Reopening an up-to-date file changes nothing.
    assert_eq!(Store::open(&p).unwrap().schema_version().unwrap(), SCHEMA_VERSION);
    // A file from a newer Vigil is left alone.
    rusqlite::Connection::open(&p).unwrap().pragma_update(None, "user_version", 99).unwrap();
    assert!(matches!(Store::open(&p), Err(StoreError::TooNew { found: 99, .. })));
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn first_seen_time_machine_and_retention() {
    let (d, root) = fixture_root("net");
    let mut s = Store::open(&d.join("vigil.db")).unwrap();
    let t0 = 1_800_000_000.0;
    let first = s.record_net(&root.net_snapshot(t0, 0)).unwrap();
    assert_eq!(first.connections, 17);
    assert!(first.new_programs.iter().any(|k| k == "/usr/lib/firefox/firefox"), "{:?}", first.new_programs);
    assert!(!first.new_destinations.is_empty());
    assert!(!first.new_destinations.iter().any(|ip| ip == "127.0.0.1" || ip == "0.0.0.0"));
    // Seen again a minute later: nothing is new, and the connections stay open.
    let again = s.record_net(&root.net_snapshot(t0 + 60.0, 0)).unwrap();
    assert!(again.new_programs.is_empty() && again.new_destinations.is_empty());
    assert_eq!(s.program_first_seen("/usr/lib/firefox/firefox").unwrap(), Some(t0));
    // The time machine: open at t0+30, nothing before t0 or long after.
    let mid = s.connections_at(t0 + 30.0, 2.0).unwrap();
    assert!(!mid.is_empty());
    assert!(mid.iter().all(|c| c.kind == "connection" && c.first_seen == t0 && c.last_seen == t0 + 60.0));
    assert!(s.connections_at(t0 - 100.0, 2.0).unwrap().is_empty());
    assert_eq!(s.connections_between(t0 - 10.0, t0 + 10.0).unwrap().len(), mid.len());
    // Processes keep (pid, start time) as identity.
    assert_eq!(s.record_processes(&root.process_list(t0, 0)).unwrap(), 13);
    // Retention: everything last seen more than a day before "now" goes.
    let gone = s.apply_retention(t0 + 3.0 * 86_400.0, 1).unwrap();
    assert!(gone >= 17 + 13, "{gone}");
    assert!(s.connections_between(0.0, f64::MAX).unwrap().is_empty());
    // First-seen memory is not history: it outlives retention, so an old friend is
    // not "new" again next week.
    assert_eq!(s.program_first_seen("/usr/lib/firefox/firefox").unwrap(), Some(t0));
    let st = s.status(30);
    assert_eq!(st.schema, SCHEMA_VERSION);
    assert!(st.programs_seen >= 5 && st.size_bytes > 0);
    std::fs::remove_dir_all(d).unwrap();
}

#[test]
fn events_and_findings_round_trip() {
    let s = Store::memory().unwrap();
    let ev = Event {
        ts: 10.0,
        kind: "sensor".into(),
        summary: "proc-poll started".into(),
        source: "vigild".into(),
        detail: serde_json::json!({"interval_ms": 2000}),
    };
    s.event(&ev).unwrap();
    assert_eq!(s.events_since(0.0, 10).unwrap(), vec![ev]);
    let f = Builder::new("tasks", "ld_preload", "game has a library forced into it", "x.", "High")
        .signal("LD_PRELOAD set", 0.9)
        .subject("4410")
        .when(5.0)
        .make()
        .unwrap();
    s.put_finding(&f, 5.0).unwrap();
    s.put_finding(&f, 9.0).unwrap();
    assert_eq!(s.findings().unwrap(), vec![f]);
}
