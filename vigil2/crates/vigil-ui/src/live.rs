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
}

pub enum Msg {
    Connected(String),
    /// Not connected, and why (in words a person can act on).
    Failed(String),
    Data(Box<Snapshot>),
    At(f64, Vec<StoredConnection>),
}

pub enum Req {
    /// The time machine: what was open at this moment.
    At(f64),
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
