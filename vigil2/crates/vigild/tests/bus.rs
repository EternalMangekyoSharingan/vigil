//! vigild end to end on a private D-Bus: the daemon reads the SYNTHETIC /proc fixture
//! (tests/fixtures/proc), serves the API, emits live updates, and refuses callers it
//! should refuse. Needs `dbus-daemon` (and `setpriv` and `dbus-send` for the refusal
//! check, which is skipped with a note when they are missing or the test is not root).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vigil_model::api::{BUS_NAME, OBJECT_PATH};
use vigil_model::host::{DaemonStatus, NetSnapshot, ProcessList};

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let t = Instant::now();
    while !ok() {
        assert!(t.elapsed() < Duration::from_secs(20), "timed out waiting for {what}");
        std::thread::yield_now();
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn private_bus(dir: &Path) -> (Kill, String) {
    let sock = dir.join("bus");
    let conf = dir.join("bus.conf");
    std::fs::write(
        &conf,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
  </policy>
</busconfig>"#,
            sock.display()
        ),
    )
    .unwrap();
    let child = Command::new("dbus-daemon")
        .args(["--nofork", "--nopidfile", &format!("--config-file={}", conf.display())])
        .stdout(Stdio::null())
        .spawn()
        .expect("dbus-daemon (install the dbus package)");
    wait_for("the private bus", || sock.exists());
    // Let other users (the refusal check) reach the socket.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o777));
    (Kill(child), format!("unix:path={}", sock.display()))
}

async fn call(conn: &zbus::Connection, iface: &str, method: &str) -> zbus::Result<String> {
    conn.call_method(Some(BUS_NAME), OBJECT_PATH, Some(iface), method, &()).await?.body().deserialize::<String>()
}

#[test]
fn serves_the_api_on_a_private_bus() {
    let dir = std::env::temp_dir().join(format!("vigild-bus-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let proc_root = dir.join("proc");
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/proc");
    vigil_sensor::procfs::materialise_fixture(&src, &proc_root).unwrap();
    let (_bus, address) = private_bus(&dir);

    let daemon = Command::new(env!("CARGO_BIN_EXE_vigild"))
        .args([
            &format!("--bus=address={address}"),
            "--auth=same-uid",
            &format!("--proc-root={}", proc_root.display()),
            &format!("--state-dir={}", dir.join("state").display()),
            "--interval-ms=150",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut daemon = Kill(daemon);

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let conn = zbus::connection::Builder::address(address.as_str()).unwrap().build().await.unwrap();
        let dbus = zbus::fdo::DBusProxy::new(&conn).await.unwrap();
        let t = Instant::now();
        while !dbus.name_has_owner(BUS_NAME.try_into().unwrap()).await.unwrap() {
            assert!(t.elapsed() < Duration::from_secs(20), "vigild did not take its name");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }

        let procs: ProcessList =
            serde_json::from_str(&call(&conn, "org.vigil.Processes", "List").await.unwrap()).unwrap();
        assert_eq!(procs.processes.len(), 13, "every process in the fixture");
        let net: NetSnapshot =
            serde_json::from_str(&call(&conn, "org.vigil.Network", "Snapshot").await.unwrap()).unwrap();
        assert_eq!(net.sockets.len(), 17);
        assert!(net.sockets.iter().any(|s| s.program.as_deref() == Some("/usr/lib/firefox/firefox")));
        let status: DaemonStatus =
            serde_json::from_str(&call(&conn, "org.vigil.Daemon", "Status").await.unwrap()).unwrap();
        assert_eq!(status.api, vigil_model::api::API_VERSION);
        assert!(status.sources.iter().any(|s| s.signal == "processes" && s.live));
        assert!(status.sources.iter().any(|s| s.signal == "dns" && !s.live), "unbuilt sources say so");
        let who: serde_json::Value =
            serde_json::from_str(&call(&conn, "org.vigil.Daemon", "Whoami").await.unwrap()).unwrap();
        assert_eq!(who["uid"], nix::unistd::getuid().as_raw());

        // One live-update signal arrives on its own.
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.vigil.Events")
            .unwrap()
            .member("Changed")
            .unwrap()
            .build();
        let mut stream = zbus::MessageStream::for_match_rule(rule, &conn, Some(4)).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            use zbus::export::futures_core::Stream;
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut stream).poll_next(cx)).await
        })
        .await
        .expect("a Changed signal within 5 s")
        .expect("stream open")
        .unwrap();
        let (kind, _ts): (String, f64) = got.body().deserialize().unwrap();
        assert_eq!(kind, "poll");

        // History: the time machine and the event log.
        let now = vigil_model::finding::now();
        let at = conn
            .call_method(Some(BUS_NAME), OBJECT_PATH, Some("org.vigil.Network"), "At", &(now,))
            .await
            .unwrap()
            .body()
            .deserialize::<String>()
            .unwrap();
        let at: Vec<serde_json::Value> = serde_json::from_str(&at).unwrap();
        assert!(!at.is_empty(), "connections open now are in the store");
        let evs = conn
            .call_method(Some(BUS_NAME), OBJECT_PATH, Some("org.vigil.Events"), "Since", &(0.0f64, 50u32))
            .await
            .unwrap()
            .body()
            .deserialize::<String>()
            .unwrap();
        assert!(evs.contains("vigild") && evs.contains("first-seen"), "{evs}");
        let none = call(&conn, "org.vigil.Findings", "List").await.unwrap();
        assert_eq!(none, "", "no checks run yet in milestone 2, so no findings");
    });

    // Another user is refused: the daemon checks the caller's uid from the bus.
    let root = nix::unistd::geteuid().is_root();
    let tools = Command::new("setpriv").arg("--version").output().is_ok()
        && Command::new("dbus-send").arg("--help").output().is_ok();
    if root && tools {
        let out = Command::new("setpriv")
            .args(["--reuid=65534", "--regid=65534", "--clear-groups", "dbus-send"])
            .args([
                &format!("--bus={address}"),
                "--print-reply",
                &format!("--dest={BUS_NAME}"),
                OBJECT_PATH,
                "org.vigil.Processes.List",
            ])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "uid 65534 must be refused");
        assert!(err.contains("AccessDenied") && err.contains("development daemon"), "{err}");
    } else {
        eprintln!("note: the refusal check needs root, setpriv and dbus-send; skipped");
    }

    // A clean stop on SIGTERM.
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(daemon.0.id() as i32), nix::sys::signal::Signal::SIGTERM)
        .unwrap();
    let status = daemon.0.wait().unwrap();
    assert!(status.success(), "vigild exits cleanly on SIGTERM: {status}");
    let _ = std::fs::remove_dir_all(dir);
}
