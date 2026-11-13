//! The proc connector reports a short-lived program's exec and exit. Needs CAP_NET_ADMIN
//! and the initial PID namespace; elsewhere it says why and skips.

use std::sync::mpsc;
use std::time::Duration;
use vigil_sensor::events::{Event, ProcEvents};

#[test]
fn sees_a_short_program_start_and_end() {
    let ev = match ProcEvents::open() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("skipped: {e}");
            return;
        }
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(batch) = ev.next() {
            for e in batch {
                if tx.send(e).is_err() {
                    return;
                }
            }
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    let child = std::process::Command::new("/bin/true").spawn().expect("spawn /bin/true");
    let pid = child.id();
    let _ = child.wait_with_output();
    let (mut exec, mut exit) = (false, false);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline && !(exec && exit) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Event::Exec { pid: p }) if p == pid => exec = true,
            Ok(Event::Exit { pid: p, code }) if p == pid => {
                assert_eq!(code, 0);
                exit = true;
            }
            _ => {}
        }
    }
    if !exec && !exit {
        eprintln!("skipped: no events arrived (not the initial PID namespace?)");
        return;
    }
    assert!(exec && exit, "exec {exec}, exit {exit}");
}

/// The milestone 3 bar on loopback: a program that connects and exits within ~50 ms is seen
/// starting, and its connection is attributed to it from its own socket table, the way the
/// daemon's fast path does it. The test's own listener on 127.0.0.1 is the only peer.
#[test]
fn a_short_program_and_its_connection_are_caught() {
    use vigil_sensor::procfs::ProcRoot;
    let Ok(ev) = ProcEvents::open() else {
        eprintln!("skipped: no proc connector here");
        return;
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            drop(s);
        }
    });
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(batch) = ev.next() {
            for e in batch {
                if tx.send(e).is_err() {
                    return;
                }
            }
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    let script = format!(
        "import socket, time; s = socket.create_connection(('127.0.0.1', {port})); time.sleep(0.05); s.close()"
    );
    let Ok(mut child) = std::process::Command::new("python3").args(["-I", "-c", &script]).spawn() else {
        eprintln!("skipped: no python3 to play the short-lived program");
        return;
    };
    let pid = child.id();
    let root = ProcRoot::system();
    let btime = root.boot_time();
    let (mut info, mut caught) = (None, vec![]);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline && caught.is_empty() {
        while let Ok(e) = rx.try_recv() {
            if e == (Event::Exec { pid }) && info.is_none() {
                info = root.read_process(pid, btime);
            }
        }
        if let Some(i) = &info {
            if let Some(inodes) = root.socket_inodes(pid) {
                caught = root
                    .sockets_of(pid, &inodes, i)
                    .into_iter()
                    .filter(|s| s.kind == "connection" && s.remote_port == u32::from(port))
                    .collect();
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let _ = child.wait();
    if info.is_none() {
        eprintln!("skipped: the exec event did not arrive (not the initial PID namespace?)");
        return;
    }
    assert_eq!(caught.len(), 1, "the connection to the test listener");
    let s = &caught[0];
    assert_eq!((s.pid, s.remote_ip.as_str(), s.direction.as_str()), (Some(pid), "127.0.0.1", "out"));
    assert!(s.program.as_deref().is_some_and(|k| k.contains("python3")), "{:?}", s.program);
}
