//! The app's link to the daemon: one background thread that finds `org.vigil.Daemon`
//! (the system bus first, then your session bus, or the bus given with `--bus`), follows
//! its `Changed` signal, and hands complete snapshots to the UI over a channel.
//!
//! The UI never waits on the bus: it reads whatever arrived last. If the daemon goes
//! away, the thread says so and keeps trying every few seconds.

use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use vigil_model::api::{BUS_NAME, IFACE_DAEMON, IFACE_EVENTS, IFACE_NETWORK, IFACE_PROCESSES, OBJECT_PATH};
use vigil_model::host::{DaemonStatus, NetSnapshot, ProcessList};
use vigil_store::{Event, StoredConnection};

/// Everything one look gives the app.
pub struct Snapshot {
    pub status: DaemonStatus,
    pub procs: ProcessList,
    pub net: NetSnapshot,
    pub events: Vec<Event>,
    /// Findings seen in the last two minutes (the current ones), newest first.
    pub findings: Vec<vigil_model::finding::Finding>,
}

pub enum Msg {
    Connected(String),
    /// Not connected, and why (in words a person can act on).
    Failed(String),
    Data(Box<Snapshot>),
    At(f64, Vec<StoredConnection>),
    /// Connections open per minute over the last hour, oldest first.
    History(Vec<f32>),
    /// What happened when asked to point out a program's window.
    Attention(String),
}

pub enum Req {
    /// The time machine: what was open at this moment.
    At(f64),
    /// Connections per minute over the last hour.
    History,
    /// Point out a program's windows: flag them in the taskbar (KDE), or post a notification.
    Attention { pids: Vec<u32>, name: String, icon: Option<String> },
}

pub fn spawn(bus: Option<String>) -> (Receiver<Msg>, Sender<Req>) {
    let (tx, rx) = mpsc::channel();
    let (req_tx, req_rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("vigil-bus".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                let _ = tx.send(Msg::Failed("could not start the bus thread".into()));
                return;
            };
            rt.block_on(run(bus, tx, req_rx));
        })
        .ok();
    (rx, req_tx)
}

async fn has_daemon(conn: &zbus::Connection) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(conn).await else { return false };
    let Ok(name) = BUS_NAME.try_into() else { return false };
    dbus.name_has_owner(name).await.unwrap_or(false)
}

async fn connect(pref: &Option<String>) -> Result<(zbus::Connection, String), String> {
    if let Some(p) = pref {
        let conn = match p.as_str() {
            "system" => zbus::Connection::system().await,
            "session" => zbus::Connection::session().await,
            a => zbus::connection::Builder::address(a.strip_prefix("address=").unwrap_or(a)).build().await,
        }
        .map_err(|e| format!("cannot reach the {p} bus: {e}"))?;
        return if has_daemon(&conn).await { Ok((conn, p.clone())) } else { Err(not_running()) };
    }
    if let Ok(c) = zbus::Connection::system().await {
        if has_daemon(&c).await {
            return Ok((c, "system".into()));
        }
    }
    if let Ok(c) = zbus::Connection::session().await {
        if has_daemon(&c).await {
            return Ok((c, "session".into()));
        }
    }
    Err(not_running())
}

fn not_running() -> String {
    "The Vigil daemon is not running.".into()
}

async fn call<A>(conn: &zbus::Connection, iface: &str, method: &str, args: &A) -> Result<String, String>
where
    A: serde::Serialize + zbus::zvariant::DynamicType,
{
    let reply = conn.call_method(Some(BUS_NAME), OBJECT_PATH, Some(iface), method, args).await.map_err(|e| {
        let t = e.to_string();
        if t.contains("AccessDenied") {
            format!("The daemon refused: {}", t.split("AccessDenied: ").last().unwrap_or(&t))
        } else {
            t
        }
    })?;
    reply.body().deserialize::<String>().map_err(|e| e.to_string())
}

fn parse<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, String> {
    serde_json::from_str(s).map_err(|e| format!("the daemon's answer was not understood: {e}"))
}

async fn look(conn: &zbus::Connection) -> Result<Snapshot, String> {
    let since = vigil_model::finding::now() - 7.0 * 86400.0;
    Ok(Snapshot {
        status: parse(&call(conn, IFACE_DAEMON, "Status", &()).await?)?,
        procs: parse(&call(conn, IFACE_PROCESSES, "List", &()).await?)?,
        net: parse(&call(conn, IFACE_NETWORK, "Snapshot", &()).await?)?,
        events: parse(&call(conn, IFACE_EVENTS, "Since", &(since, 300u32)).await?)?,
        // An older daemon has no Recent method: no findings rather than no data.
        findings: call(conn, "org.vigil.Findings", "Recent", &(vigil_model::finding::now() - 120.0,))
            .await
            .ok()
            .and_then(|t| vigil_model::finding::from_jsonl(&t, false).ok())
            .map(|i| i.0)
            .unwrap_or_default(),
    })
}

async fn run(pref: Option<String>, tx: Sender<Msg>, req: Receiver<Req>) {
    use zbus::export::futures_core::Stream;
    loop {
        let (conn, bus) = match connect(&pref).await {
            Ok(c) => c,
            Err(e) => {
                if tx.send(Msg::Failed(e)).is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };
        let _ = tx.send(Msg::Connected(bus));
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(BUS_NAME)
            .interface(IFACE_EVENTS)
            .member("Changed")
            .build();
        let mut stream = match rule {
            Ok(r) => zbus::MessageStream::for_match_rule(r, &conn, std::num::NonZeroUsize::new(4)).await.ok(),
            Err(_) => None,
        };
        loop {
            match look(&conn).await {
                Ok(s) => {
                    if tx.send(Msg::Data(Box::new(s))).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Msg::Failed(e));
                    break;
                }
            }
            // Wait for the next Changed signal (or 5 s), answering requests meanwhile.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                while let Ok(r) = req.try_recv() {
                    match r {
                        Req::At(t) => {
                            if let Ok(text) = call(&conn, IFACE_NETWORK, "At", &(t,)).await {
                                if let Ok(rows) = parse(&text) {
                                    let _ = tx.send(Msg::At(t, rows));
                                }
                            }
                        }
                        Req::History => {
                            let now = vigil_model::finding::now();
                            if let Ok(text) = call(&conn, IFACE_NETWORK, "Between", &(now - 3600.0, now)).await {
                                if let Ok(rows) = parse::<Vec<StoredConnection>>(&text) {
                                    let _ = tx.send(Msg::History(per_minute(&rows, now)));
                                }
                            }
                        }
                        Req::Attention { pids, name, icon } => {
                            let _ = tx.send(Msg::Attention(attention(&pids, &name, icon.as_deref()).await));
                        }
                    }
                }
                let tick = tokio::time::sleep(Duration::from_millis(150));
                let next = async {
                    match stream.as_mut() {
                        Some(s) => std::future::poll_fn(|cx| std::pin::Pin::new(&mut *s).poll_next(cx)).await.is_some(),
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    got = next => if got { break },
                    _ = tick => {}
                }
                if tokio::time::Instant::now() > deadline {
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Connections open in each minute of the last hour (60 values, oldest first).
pub fn per_minute(rows: &[StoredConnection], now: f64) -> Vec<f32> {
    (0..60)
        .map(|m| {
            let t = now - 3600.0 + 60.0 * (m as f64 + 0.5);
            rows.iter().filter(|c| c.first_seen <= t && c.last_seen + 2.5 >= t).count() as f32
        })
        .collect()
}

/// Flag a program's windows in the taskbar. On KDE Plasma a tiny KWin script sets
/// `demandsAttention` on every window owned by one of `pids` (the taskbar entry pulses
/// until you look at it). Elsewhere, a desktop notification names the program instead.
/// Both stay on this machine (the session bus).
async fn attention(pids: &[u32], name: &str, icon: Option<&str>) -> String {
    let Ok(session) = zbus::Connection::session().await else {
        return "no desktop session bus to talk to".into();
    };
    if has_name(&session, "org.kde.KWin").await {
        let list = pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        let script = format!(
            "const pids = [{list}];\nconst wins = workspace.windowList ? workspace.windowList() : workspace.clientList();\n\
             for (const w of wins) {{ if (pids.includes(w.pid)) {{ w.demandsAttention = true; }} }}\n"
        );
        let dir = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let path = dir.join("vigil-attention.js");
        if std::fs::write(&path, script).is_ok() {
            let plugin = "vigil-attention";
            let scripting = |m: &'static str| (Some("org.kde.KWin"), "/Scripting", Some("org.kde.kwin.Scripting"), m);
            let (d, p, i, m) = scripting("unloadScript");
            let _ = session.call_method(d, p, i, m, &(plugin,)).await;
            let (d, p, i, m) = scripting("loadScript");
            if let Ok(reply) = session.call_method(d, p, i, m, &(path.to_string_lossy().as_ref(), plugin)).await {
                if let Ok(id) = reply.body().deserialize::<i32>() {
                    for obj in [format!("/Scripting/Script{id}"), format!("/{id}")] {
                        if session
                            .call_method(Some("org.kde.KWin"), obj.as_str(), Some("org.kde.kwin.Script"), "run", &())
                            .await
                            .is_ok()
                        {
                            return format!("{name} is flagged in your taskbar");
                        }
                    }
                }
            }
        }
    }
    let hints: std::collections::HashMap<&str, zbus::Variant<'_>> = std::collections::HashMap::new();
    let actions: Vec<&str> = vec![];
    let sent = session
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "Vigil",
                0u32,
                icon.unwrap_or("org.vigil.Vigil"),
                name,
                "Selected in Vigil's network view",
                actions,
                hints,
                4000i32,
            ),
        )
        .await;
    match sent {
        Ok(_) => format!("Sent a notification for {name}"),
        Err(e) => format!("Could not point out {name}: {e}"),
    }
}

async fn has_name(conn: &zbus::Connection, name: &str) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(conn).await else { return false };
    let Ok(n) = name.try_into() else { return false };
    dbus.name_has_owner(n).await.unwrap_or(false)
}
