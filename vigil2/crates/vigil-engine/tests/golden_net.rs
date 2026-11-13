//! Network scoring and alert wording must agree with Vigil 1 on tests/golden/net.json
//! (SYNTHETIC connection histories, in UTC). Regenerate with tests/golden/make_golden.py.

use serde_json::Value;
use std::collections::HashMap;
use vigil_engine::net::{self, Alert, Conn, Context, Pair, ProgInfo, ProgramRow, Rule};

fn golden() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/net.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("net.json")).expect("json")
}

/// JSON equality where numbers only need to agree to 1e-9 (Python sums fractions exactly).
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let (x, y) = (x.as_f64().unwrap_or(f64::NAN), y.as_f64().unwrap_or(f64::NAN));
            (x - y).abs() <= 1e-9 * x.abs().max(1.0)
        }
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

fn check(what: &str, got: Value, want: &Value) {
    assert!(same(&got, want), "{what}\n got: {got}\nwant: {want}");
}

fn conns(v: &Value) -> Vec<Conn> {
    serde_json::from_value(v.clone()).expect("conns")
}

#[test]
fn beacon_statistics_match_vigil_1() {
    let g = golden();
    for (name, times) in g["series"].as_object().expect("series") {
        let t: Vec<f64> = serde_json::from_value(times.clone()).expect("times");
        let got = net::beacon_stats(&t, 2.0).map(|b| serde_json::to_value(b).expect("stats"));
        check(name, got.unwrap_or(Value::Null), &g["beacon_stats"][name]);
        let cs: Vec<Conn> = t
            .iter()
            .enumerate()
            .map(|(i, x)| Conn {
                id: i as i64 + 1,
                opened_at: *x,
                closed_at: Some(x + 1.0),
                bytes_sent: None,
                bytes_recv: None,
                local_port: 40000 + i as u32,
            })
            .collect();
        let got = serde_json::to_value(net::beacon_findings(&cs, 2.0, "tcp 203.0.113.7:443", 0)).expect("findings");
        check(name, got, &g["beacon_findings"][name]);
    }
}

#[test]
fn long_connections_and_locations_match_vigil_1() {
    let g = golden();
    let (t0, now) = (g["t0"].as_f64().expect("t0"), g["now"].as_f64().expect("now"));
    for (name, cs) in g["long"]["cases"].as_object().expect("long") {
        let got = serde_json::to_value(net::long_connection_finding(&conns(cs), now, Some(t0), 0)).expect("long");
        check(name, got, &g["long"]["findings"][name]);
    }
    for (name, case) in g["location"]["cases"].as_object().expect("loc") {
        let info: ProgInfo = serde_json::from_value(case[0].clone()).expect("info");
        let got = serde_json::to_value(net::location_findings(&info, case[1].as_str().expect("key"))).expect("loc");
        check(name, got, &g["location"]["findings"][name]);
    }
}

#[test]
fn allowlist_rules_match_vigil_1() {
    let g = golden();
    let mut rules = net::builtin_rules();
    let user: Vec<Rule> = serde_json::from_value(g["rules"]["user"].clone()).expect("rules");
    rules.extend(user);
    let pairs: Vec<Pair> = serde_json::from_value(g["rules"]["pairs"].clone()).expect("pairs");
    for (p, want) in pairs.iter().zip(g["rules"]["hits"].as_array().expect("hits")) {
        assert_eq!(net::first_match(&rules, p).map(|r| r.id.as_str()), want.as_str(), "{p:?}");
    }
}

#[test]
fn scored_pairs_and_their_words_match_vigil_1() {
    let g = golden();
    let cx_json = &g["context"];
    let mut programs = HashMap::new();
    for (k, p) in cx_json["programs"].as_object().expect("programs") {
        let info: ProgInfo = serde_json::from_str(p["info"].as_str().expect("info")).expect("info json");
        programs.insert(
            k.clone(),
            ProgramRow {
                name: p["name"].as_str().expect("name").into(),
                first_outbound: p["first_outbound"].as_f64(),
                hidden: false,
                info,
            },
        );
    }
    let cx = Context {
        now: g["now"].as_f64().expect("now"),
        baseline: g["t0"].as_f64(),
        programs,
        destinations: cx_json["destinations"]
            .as_object()
            .expect("dests")
            .iter()
            .map(|(k, v)| {
                (k.clone(), (v["first_seen"].as_f64().expect("first"), v["scope"].as_str().unwrap_or("").to_string()))
            })
            .collect(),
        prevalence: cx_json["prevalence"]
            .as_object()
            .expect("prev")
            .iter()
            .map(|(k, v)| (k.clone(), (v[0].as_u64().expect("n") as usize, v[1].as_u64().expect("c") as usize)))
            .collect(),
        poll: 2.0,
        utc_offset: 0,
    };
    for (name, case) in g["pairs"].as_object().expect("pairs") {
        let k = &case["key"];
        let key = (
            k[0].as_str().expect("program"),
            k[1].as_str().expect("ip"),
            k[2].as_u64().expect("port") as u32,
            k[3].as_str().expect("proto"),
            k[4].as_str().expect("direction"),
        );
        let (pair, score, fs) = net::score_pair(key, &conns(&case["conns"]), &cx);
        check(&format!("{name} pair"), serde_json::to_value(&pair).expect("pair"), &case["pair"]);
        check(&format!("{name} score"), serde_json::json!(score), &case["score"]);
        check(&format!("{name} findings"), serde_json::to_value(&fs).expect("fs"), &case["findings"]);
        let prog = &cx.programs[key.0];
        let a = Alert {
            pair: &pair,
            score,
            findings: &fs,
            name: Some(&prog.name),
            exe: prog.info.exe.as_deref(),
            hidden: None,
            first_raised: cx.now,
            now: cx.now,
            utc_offset: 0,
        };
        let view = &case["view"];
        assert_eq!(a.title(), view["title"].as_str().expect("title"), "{name}");
        assert_eq!(a.severity(), view["severity"].as_str().expect("sev"), "{name}");
        assert_eq!(a.who().as_deref(), view["who"].as_str(), "{name}");
        assert_eq!(a.to(), view["to"].as_str().expect("to"), "{name}");
        let ex = &case["explain"];
        assert_eq!(a.summary(), ex["summary"].as_str().expect("summary"), "{name}");
        let sigs: Vec<Value> = a
            .signals()
            .into_iter()
            .map(|(k, t, s)| serde_json::json!({"signal": k, "text": t, "strength": s}))
            .collect();
        check(&format!("{name} signals"), Value::Array(sigs), &ex["signals"]);
        let why: Vec<Value> = a.why().into_iter().map(|(g, t)| serde_json::json!({"group": g, "text": t})).collect();
        check(&format!("{name} why"), Value::Array(why), &ex["why"]);
        let (level, reason) = a.confidence();
        check(&format!("{name} confidence"), serde_json::json!({"level": level, "reason": reason}), &ex["confidence"]);
        let osr = vigil_model::distro::parse_os_release("ID=fedora\n");
        a.finding(&osr).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

/// A whole run on SYNTHETIC rows: a program in /tmp beaconing to a new address alerts once
/// (two ports, one alert); the same traffic from an allowlisted program does not; neither
/// does a plain timer from an installed program, which stays under the threshold.
#[test]
fn a_scoring_run_raises_only_what_it_should() {
    let t0 = 1_790_000_000.0;
    let now = t0 + 6.0 * 3600.0;
    let mut rows = vec![];
    let mut id = 0;
    let mut add = |program: &str, ip: &str, port: u32, start: f64, every: f64, n: usize| {
        for i in 0..n {
            id += 1;
            let t = start + every * i as f64;
            rows.push(net::Row {
                id,
                program: program.into(),
                ip: ip.into(),
                direction: "out".into(),
                proto: "tcp".into(),
                local_port: 40_000 + id as u32,
                remote_port: port,
                first_seen: t,
                last_seen: t + 1.0,
            });
        }
    };
    add("/tmp/.x/agent", "203.0.113.10", 4444, t0 + 3600.0, 60.0, 40);
    add("/tmp/.x/agent", "203.0.113.10", 8443, t0 + 3700.0, 600.0, 3);
    add("/usr/sbin/chronyd", "162.159.200.1", 123, t0, 64.0, 60);
    add("/usr/bin/syncd", "198.51.100.20", 443, t0, 300.0, 30);
    let mut programs = HashMap::new();
    for (k, first) in [("/tmp/.x/agent", t0 + 3600.0), ("/usr/sbin/chronyd", t0), ("/usr/bin/syncd", t0)] {
        programs.insert(
            k.to_string(),
            ProgramRow {
                name: k.rsplit('/').next().unwrap_or(k).into(),
                first_outbound: Some(first),
                hidden: false,
                info: ProgInfo { exe: Some(k.into()), pid: Some(7), exe_deleted: false },
            },
        );
    }
    let cx = Context {
        now,
        baseline: Some(t0),
        programs,
        destinations: [("203.0.113.10".to_string(), (t0 + 3600.0, "internet".to_string()))].into_iter().collect(),
        prevalence: HashMap::new(),
        poll: 2.0,
        utc_offset: 0,
    };
    let results = net::run(&rows, &cx, &net::builtin_rules());
    assert_eq!(results.len(), 4, "four pairs");
    let alerts = net::alerts(&results);
    assert_eq!(alerts.len(), 1, "one alert for the agent, not one per port");
    assert_eq!(alerts[0].pair.program, "/tmp/.x/agent");
    assert_eq!(alerts[0].pair.port, 4444, "the higher-scoring port");
    let chrony = results.iter().find(|r| r.pair.program.ends_with("chronyd")).expect("chrony");
    assert!(chrony.rule.as_ref().is_some_and(|r| r.id == "builtin-chrony"), "chrony is allowlisted");
    let syncd = results.iter().find(|r| r.pair.program.ends_with("syncd")).expect("syncd");
    assert!(syncd.score < net::ALERT_THRESHOLD && syncd.rule.is_none(), "a timer alone never alerts");
    // The same agent traffic, allowlisted by the user, raises nothing.
    let mut rules = net::builtin_rules();
    rules.push(Rule {
        id: "user-1".into(),
        program: Some("/tmp/.x/agent".into()),
        ip: None,
        port: None,
        proto: None,
        direction: None,
        reason: "SYNTHETIC test rule".into(),
        enabled: true,
    });
    assert!(net::alerts(&net::run(&rows, &cx, &rules)).is_empty());
}
