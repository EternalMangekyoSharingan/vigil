//! Who is calling, and may they? (docs/DECISIONS.md D-008)
//!
//! Every method call: the bus tells us the caller's uid and pid
//! (`GetConnectionCredentials`, filled by the bus from SO_PEERCRED). Then:
//! - **Polkit** (the system service): ask polkit whether that caller may perform the
//!   action. polkit decides from its policy (packaging/polkit/org.vigil.policy) and the
//!   caller's session, and shows the system's own password dialog when the policy says
//!   so. Vigil never sees a password. If polkit cannot be reached, the answer is no.
//! - **SameUid** (development, `--bus session`): only callers with the daemon's own uid.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zbus::fdo;
use zbus::message::Header;
use zbus::Connection;
use zbus::Variant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Polkit,
    SameUid(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub uid: u32,
    pub pid: Option<u32>,
    pub bus_name: String,
}

/// Reading is asked often (every refresh); polkit's answer is kept for a few seconds per
/// caller. Privileged actions are never cached.
const READ_CACHE: Duration = Duration::from_secs(10);

pub struct Authorizer {
    pub mode: Mode,
    cache: Mutex<HashMap<(String, String), Instant>>,
}

impl Authorizer {
    pub fn new(mode: Mode) -> Self {
        Authorizer { mode, cache: Mutex::new(HashMap::new()) }
    }

    pub async fn caller(conn: &Connection, hdr: &Header<'_>) -> fdo::Result<Caller> {
        let sender = hdr.sender().ok_or_else(|| fdo::Error::AccessDenied("no sender on the message".into()))?;
        let dbus = fdo::DBusProxy::new(conn).await?;
        let creds = dbus.get_connection_credentials(sender.clone().into()).await?;
        let uid = creds
            .unix_user_id()
            .ok_or_else(|| fdo::Error::AccessDenied("the bus did not give the caller's uid".into()))?;
        Ok(Caller { uid, pid: creds.process_id(), bus_name: sender.to_string() })
    }

    /// May `caller` perform `action`? `interactive` lets polkit show its dialog.
    pub async fn check(&self, conn: &Connection, caller: &Caller, action: &str, interactive: bool) -> fdo::Result<()> {
        match self.mode {
            Mode::SameUid(uid) if caller.uid == uid => Ok(()),
            Mode::SameUid(uid) => Err(fdo::Error::AccessDenied(format!(
                "this is a development daemon running as uid {uid}; it answers only that user (caller uid {})",
                caller.uid
            ))),
            Mode::Polkit => {
                let key = (caller.bus_name.clone(), action.to_string());
                let cacheable = action == vigil_model::api::ACTION_READ;
                if cacheable {
                    let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                    if cache.get(&key).is_some_and(|t| t.elapsed() < READ_CACHE) {
                        return Ok(());
                    }
                }
                polkit_check(conn, caller, action, interactive).await?;
                if cacheable {
                    let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                    cache.retain(|_, t| t.elapsed() < READ_CACHE);
                    cache.insert(key, Instant::now());
                }
                Ok(())
            }
        }
    }
}

/// org.freedesktop.PolicyKit1.Authority.CheckAuthorization for a bus-name subject.
async fn polkit_check(conn: &Connection, caller: &Caller, action: &str, interactive: bool) -> fdo::Result<()> {
    let mut subject_details: HashMap<&str, Variant<'_>> = HashMap::new();
    subject_details.insert("name", Variant::from(caller.bus_name.as_str()));
    let subject = ("system-bus-name", subject_details);
    let details: HashMap<&str, &str> = HashMap::new();
    let flags: u32 = u32::from(interactive); // 1 = AllowUserInteraction
    let reply = conn
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(subject, action, details, flags, ""),
        )
        .await
        .map_err(|e| {
            let text = e.to_string();
            fdo::Error::AccessDenied(if text.contains("NotAuthorized") {
                format!(
                    "polkit will not answer vigild's question ({text}). The installed org.vigil.policy must name \
                     the vigil account as owner of {action}; reinstall the package. Vigil refuses rather than guess."
                )
            } else {
                format!("polkit could not be asked ({text}); Vigil refuses rather than guess. Run `vigil-cli doctor`.")
            })
        })?;
    let (authorized, challenge, _details): (bool, bool, HashMap<String, String>) =
        reply.body().deserialize().map_err(|e| fdo::Error::Failed(format!("polkit's answer was unreadable: {e}")))?;
    if authorized {
        return Ok(());
    }
    Err(fdo::Error::AccessDenied(if challenge {
        format!(
            "{action} needs an administrator password, and this request could not show the password dialog \
             (uid {}). Run Vigil from your desktop session, or as an administrator.",
            caller.uid
        )
    } else {
        format!("polkit does not allow uid {} to use {action}", caller.uid)
    }))
}
