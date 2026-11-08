//! sd_notify without a library: tell systemd we are ready, alive, or stopping.
//! (`Type=notify` and `WatchdogSec=` in packaging/systemd/vigild.service.)

use std::os::unix::net::UnixDatagram;
use std::time::Duration;

/// Send one notification ("READY=1", "WATCHDOG=1", "STOPPING=1", "STATUS=..."). Does
/// nothing when not started by systemd.
pub fn notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return };
    let Ok(sock) = UnixDatagram::unbound() else { return };
    let path = path.to_string_lossy().into_owned();
    if let Some(name) = path.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()) {
            let _ = sock.send_to_addr(state.as_bytes(), &addr);
        }
    } else {
        let _ = sock.send_to(state.as_bytes(), &path);
    }
}

/// How often to ping the watchdog: half the interval systemd gave us, if any.
pub fn watchdog_interval() -> Option<Duration> {
    let us: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    let pid_ok =
        std::env::var("WATCHDOG_PID").ok().and_then(|p| p.parse::<u32>().ok()).is_none_or(|p| p == std::process::id());
    (pid_ok && us > 0).then(|| Duration::from_micros(us / 2))
}
