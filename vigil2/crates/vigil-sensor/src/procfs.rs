//! The /proc fallback source: socket tables and processes, read by polling.
//!
//! Port of Vigil 1's `vigil/net/collector.py`. It reads the kernel's socket tables
//! (`/proc/net/tcp`, `tcp6`, `udp`, `udp6`) and maps each socket to the process holding it
//! by scanning `/proc/<pid>/fd`. When the kernel will not say who owns a socket, the
//! socket is still reported, with the reason it could not be attributed.
//!
//! Polling misses anything that starts and ends between two looks (milestone 3 adds
//! event sources). It is kept forever as the fallback that works on every kernel.
//!
//! Nothing here writes to /proc or changes any setting.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::path::{Path, PathBuf};
pub use vigil_model::netaddr::scope_of;

use vigil_model::host::{Ancestor, Hidden, NetSnapshot, ProcessInfo, ProcessList, Socket, Viewer};

pub const TABLES: [&str; 4] = ["tcp", "tcp6", "udp", "udp6"];
/// Linux keeps a closed TCP connection in TIME_WAIT for a fixed 60 s, and /proc prints
/// the time left. That dates the close even if Vigil never saw it open.
pub const TIME_WAIT_SECONDS: f64 = 60.0;
/// USER_HZ: the unit of /proc's clock ticks. 100 on every Linux architecture Vigil runs on.
pub const CLK_TCK: f64 = 100.0;
const ANCESTRY_DEPTH: usize = 12;

fn tcp_state(code: u32) -> Option<&'static str> {
    Some(match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        0x0C => "NEW_SYN_RECV",
        _ => return None,
    })
}

/// UDP has no handshake; the kernel reuses two TCP codes for it.
fn udp_state(code: u32) -> Option<&'static str> {
    match code {
        0x01 => Some("ESTABLISHED"),
        0x07 => Some("UNCONN"),
        _ => None,
    }
}

/// How the sensor reads /proc. Tests replace the root and can make chosen pids
/// unreadable, the way the kernel hides other users' processes from a normal user.
#[derive(Debug, Clone)]
pub struct ProcRoot {
    pub root: PathBuf,
    /// Pids whose fd/ and exe this view may not read (tests only; the kernel does it
    /// for real when the daemon lacks CAP_SYS_PTRACE).
    pub blocked: HashSet<u32>,
    /// Turns a uid into a user name. The daemon uses the system's user database.
    pub user_name: fn(u32) -> String,
}

/// The system's user database (NSS), or "uid N" when the uid has no name.
///
/// Answers are kept for ten minutes. Each NSS lookup opens /etc/passwd (or asks
/// systemd-userdb); doing that for every process on every look cost real CPU, and on
/// systems with fapolicyd it made fapolicyd vet hundreds of opens a second.
pub fn system_user_name(uid: u32) -> String {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    type Cache = Mutex<HashMap<u32, (String, Instant)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    const KEEP: Duration = Duration::from_secs(600);
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some((name, at)) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&uid) {
        if at.elapsed() < KEEP {
            return name.clone();
        }
    }
    let name = match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
        Ok(Some(u)) => u.name,
        _ => format!("uid {uid}"),
    };
    cache.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, (name.clone(), Instant::now()));
    name
}

impl ProcRoot {
    pub fn system() -> ProcRoot {
        ProcRoot { root: PathBuf::from("/proc"), blocked: HashSet::new(), user_name: system_user_name }
    }

    pub fn at(root: impl Into<PathBuf>) -> ProcRoot {
        ProcRoot { root: root.into(), ..ProcRoot::system() }
    }

    fn pid_of(&self, path: &Path) -> Option<u32> {
        path.strip_prefix(&self.root).ok()?.components().next()?.as_os_str().to_str()?.parse().ok()
    }

    fn denied(&self, path: &Path) -> io::Result<()> {
        if self.pid_of(path).is_some_and(|p| self.blocked.contains(&p)) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(())
    }

    fn read(&self, rel: &str) -> io::Result<String> {
        std::fs::read_to_string(self.root.join(rel))
    }

    fn read_bytes(&self, rel: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.root.join(rel))
    }

    fn list_fd(&self, pid: u32) -> io::Result<Vec<String>> {
        let p = self.root.join(format!("{pid}/fd"));
        self.denied(&p)?;
        Ok(std::fs::read_dir(p)?.filter_map(|e| e.ok()?.file_name().into_string().ok()).collect())
    }

    fn readlink(&self, rel: &str) -> io::Result<String> {
        let p = self.root.join(rel);
        self.denied(&p)?;
        Ok(std::fs::read_link(p)?.to_string_lossy().into_owned())
    }

    /// The files a process has open, by readlink on /proc/<pid>/fd (no file is opened), up to
    /// 4096 of them; None when the kernel will not show its fd table.
    pub fn open_files(&self, pid: u32) -> Option<Vec<String>> {
        let fds = self.list_fd(pid).ok()?;
        Some(
            fds.iter()
                .take(4096)
                .filter_map(|fd| self.readlink(&format!("{pid}/fd/{fd}")).ok())
                .filter(|t| t.starts_with('/'))
                .map(|t| t.strip_suffix(" (deleted)").map(str::to_string).unwrap_or(t))
                .collect(),
        )
    }

    /// Only the dynamic linker's variables (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH) from a
    /// process's environment, values cut at 500 characters. The rest of the environment
    /// (tokens, passwords) is scanned for these names only and never kept. None if unreadable.
    pub fn ld_vars(&self, pid: u32) -> Option<BTreeMap<String, String>> {
        let p = self.root.join(format!("{pid}/environ"));
        self.denied(&p).ok()?;
        let raw = std::fs::read(p).ok()?;
        let raw = &raw[..raw.len().min(1 << 20)];
        let mut out = BTreeMap::new();
        for item in raw.split(|b| *b == 0) {
            for var in ["LD_PRELOAD=", "LD_AUDIT=", "LD_LIBRARY_PATH="] {
                if let Some(v) = item.strip_prefix(var.as_bytes()) {
                    let v: String = String::from_utf8_lossy(v).chars().take(500).collect();
                    out.insert(var.trim_end_matches('=').to_string(), v);
                }
            }
        }
        Some(out)
    }

    /// Every numeric entry of /proc.
    pub fn pids(&self) -> Vec<u32> {
        let Ok(dir) = std::fs::read_dir(&self.root) else { return vec![] };
        let mut pids: Vec<u32> = dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect();
        pids.sort_unstable();
        pids
    }

    fn status(&self, pid: u32) -> io::Result<BTreeMap<String, String>> {
        Ok(self
            .read(&format!("{pid}/status"))?
            .lines()
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.to_string(), v.trim().to_string())))
            .collect())
    }

    fn uid_of(&self, pid: u32) -> io::Result<i64> {
        let st = self.status(pid)?;
        Ok(st.get("Uid").and_then(|u| u.split_whitespace().next()).and_then(|u| u.parse().ok()).unwrap_or(-1))
    }

    /// Boot time (seconds since the epoch), from /proc/stat.
    pub fn boot_time(&self) -> Option<i64> {
        self.read("stat").ok()?.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())
    }

    /// Process start, from field 22 of /proc/<pid>/stat. The name field may contain
    /// spaces and ')', so fields are counted from the last ')'.
    fn start_time(&self, pid: u32, btime: Option<i64>) -> Option<f64> {
        let btime = btime?;
        let stat = self.read(&format!("{pid}/stat")).ok()?;
        let rest = stat.get(stat.rfind(')')? + 2..)?;
        let ticks: f64 = rest.split_whitespace().nth(19)?.parse::<i64>().ok()? as f64;
        Some(btime as f64 + ticks / CLK_TCK)
    }

    /// Identity and context for one process, or None if it has exited.
    pub fn read_process(&self, pid: u32, btime: Option<i64>) -> Option<ProcessInfo> {
        let status = self.status(pid).ok()?;
        let comm = self.read(&format!("{pid}/comm")).ok()?.trim().to_string();
        let mut cmdline: Vec<String> = match self.read_bytes(&format!("{pid}/cmdline")) {
            Ok(b) => String::from_utf8_lossy(&b).split('\0').map(String::from).collect(),
            Err(_) => vec![],
        };
        while cmdline.last().is_some_and(|s| s.is_empty()) {
            cmdline.pop();
        }
        let exe = self.readlink(&format!("{pid}/exe")).ok();
        let uid: i64 =
            status.get("Uid").and_then(|u| u.split_whitespace().next()).and_then(|u| u.parse().ok()).unwrap_or(-1);
        let ppid: u32 = status.get("PPid").and_then(|p| p.parse().ok()).unwrap_or(0);
        let (key, name) = program_identity(exe.as_deref(), &cmdline, &comm);
        let mut ancestry = vec![];
        let mut p = ppid;
        while p > 0 && ancestry.len() < ANCESTRY_DEPTH {
            let Ok(pst) = self.status(p) else { break };
            ancestry.push(Ancestor {
                pid: p,
                name: pst.get("Name").cloned().unwrap_or_else(|| "?".into()),
                started: self.start_time(p, btime),
            });
            p = pst.get("PPid").and_then(|x| x.parse().ok()).unwrap_or(0);
        }
        Some(ProcessInfo {
            pid,
            key,
            name,
            comm,
            exe_deleted: exe.as_deref().is_some_and(|e| e.ends_with(" (deleted)")),
            exe,
            cmdline,
            uid,
            user: if uid >= 0 { (self.user_name)(uid as u32) } else { "uid -1".into() },
            ppid,
            parent: ancestry.first().map(|a| a.name.clone()),
            ancestry,
            started: self.start_time(pid, btime),
            rss_kb: None,
            cpu_pct: None,
        })
    }

    /// CPU time used so far (clock ticks, user + system) and resident memory (kB).
    pub fn usage(&self, pid: u32) -> Option<(u64, u64)> {
        let stat = self.read(&format!("{pid}/stat")).ok()?;
        let f: Vec<&str> = stat.get(stat.rfind(')')? + 2..)?.split_whitespace().collect();
        let ticks = f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?;
        let pages: u64 = self.read(&format!("{pid}/statm")).ok()?.split_whitespace().nth(1)?.parse().ok()?;
        Some((ticks, pages * 4))
    }

    /// Map socket inodes to the pids holding them: (every pid, {inode: pids}, the pids
    /// whose fd table the kernel would not show).
    pub fn scan_fds(&self) -> (Vec<u32>, BTreeMap<u64, Vec<u32>>, Vec<u32>) {
        let (mut pids, mut owners, mut unreadable) = (vec![], BTreeMap::<u64, Vec<u32>>::new(), vec![]);
        for pid in self.pids() {
            pids.push(pid);
            let fds = match self.list_fd(pid) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    unreadable.push(pid);
                    continue;
                }
                Err(_) => continue, // exited while we looked
            };
            for fd in fds {
                let Ok(target) = self.readlink(&format!("{pid}/fd/{fd}")) else { continue };
                if let Some(inode) = target.strip_prefix("socket:[").and_then(|t| t.strip_suffix(']')) {
                    if let Ok(i) = inode.parse() {
                        owners.entry(i).or_default().push(pid);
                    }
                }
            }
        }
        (pids, owners, unreadable)
    }

    fn unreadable_by_uid(&self, unreadable: &[u32]) -> BTreeMap<u32, usize> {
        let mut out = BTreeMap::new();
        for pid in unreadable {
            if let Ok(uid) = self.uid_of(*pid) {
                *out.entry(uid as u32).or_insert(0) += 1;
            }
        }
        out
    }

    fn viewer(&self, uid: u32) -> Viewer {
        Viewer { uid, user: (self.user_name)(uid), root: uid == 0 }
    }

    /// One read-only pass: sockets, their processes, and what is hidden.
    pub fn net_snapshot(&self, now: f64, viewer_uid: u32) -> NetSnapshot {
        let mut sockets = vec![];
        let mut missing = vec![];
        for table in TABLES {
            match self.read(&format!("net/{table}")) {
                Ok(text) => sockets.extend(parse_table(&text, table)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(table.to_string()),
                Err(_) => {}
            }
        }
        // A connection on a port we listen on was accepted from outside: "in".
        let listening: HashSet<(String, u32)> = sockets
            .iter()
            .filter(|s| s.kind == "listen" && s.state == "LISTEN")
            .map(|s| (s.proto.clone(), s.local_port))
            .collect();
        for s in sockets.iter_mut() {
            let inbound = s.kind == "connection" && listening.contains(&(s.proto.clone(), s.local_port));
            s.direction = if inbound { "in" } else { "out" }.into();
        }
        let (pids, owners, unreadable) = self.scan_fds();
        let unreadable_by_uid = self.unreadable_by_uid(&unreadable);
        let protected = if viewer_uid != 0 { unreadable_by_uid.get(&viewer_uid).copied().unwrap_or(0) } else { 0 };
        let btime = self.boot_time();
        let mut processes: BTreeMap<u32, Option<ProcessInfo>> = BTreeMap::new();
        let mut hidden_counts: BTreeMap<String, usize> = BTreeMap::new();
        for s in sockets.iter_mut() {
            let mut holders: Vec<u32> =
                if s.inode != 0 { owners.get(&s.inode).cloned().unwrap_or_default() } else { vec![] };
            holders.sort_unstable();
            for pid in &holders {
                processes.entry(*pid).or_insert_with(|| self.read_process(*pid, btime));
            }
            let live: Vec<u32> =
                holders.into_iter().filter(|p| processes.get(p).is_some_and(Option::is_some)).collect();
            if let Some(first) = live.first() {
                s.pid = Some(*first);
                s.program = processes[first].as_ref().map(|p| p.key.clone());
                s.pids = live;
                s.hidden = None;
                continue;
            }
            let reason = if s.inode == 0 {
                "closed"
            } else if viewer_uid != 0 && s.uid != viewer_uid {
                "other-user"
            } else if protected > 0 {
                "protected"
            } else {
                "unknown"
            };
            s.pid = None;
            s.pids = vec![];
            s.program = None;
            s.hidden = Some(Hidden {
                reason: reason.into(),
                label: hidden_label(reason).into(),
                explanation: self.explain_hidden(reason, s, viewer_uid, protected),
            });
            *hidden_counts.entry(reason.into()).or_insert(0) += 1;
        }
        let real = self.root == Path::new("/proc");
        NetSnapshot {
            taken_at: now,
            viewer: self.viewer(viewer_uid),
            sockets,
            processes: processes.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))).collect(),
            pids_visible: pids.len(),
            unreadable_by_uid,
            hidden_counts,
            missing_tables: missing,
            byte_counts: false,
            hidepid: if real { hidepid_option(Path::new("/proc/self/mountinfo")) } else { None },
        }
    }

    /// Every visible process.
    pub fn process_list(&self, now: f64, viewer_uid: u32) -> ProcessList {
        let btime = self.boot_time();
        let pids = self.pids();
        let processes: Vec<ProcessInfo> = pids.iter().filter_map(|p| self.read_process(*p, btime)).collect();
        let unreadable: Vec<u32> = pids
            .iter()
            .copied()
            .filter(|p| matches!(self.list_fd(*p), Err(e) if e.kind() == io::ErrorKind::PermissionDenied))
            .collect();
        let real = self.root == Path::new("/proc");
        ProcessList {
            taken_at: now,
            viewer: self.viewer(viewer_uid),
            processes,
            unreadable_by_uid: self.unreadable_by_uid(&unreadable),
            hidepid: if real { hidepid_option(Path::new("/proc/self/mountinfo")) } else { None },
        }
    }

    /// Plain-language reason a socket has no process attached.
    fn explain_hidden(&self, reason: &str, s: &Socket, viewer_uid: u32, protected: usize) -> String {
        match reason {
            "closed" => format!(
                "The program already closed this connection; the kernel keeps it in {} to finish the shutdown, \
                 and no process owns it any more.",
                s.state
            ),
            "other-user" => format!(
                "Owned by {} (uid {}). The kernel shows a process's open sockets only to its owner and to root, so \
                 Vigil, running as {}, cannot see which program this is.",
                (self.user_name)(s.uid),
                s.uid,
                (self.user_name)(viewer_uid)
            ),
            "protected" => format!(
                "Owned by your user, but {protected} of your processes do not allow inspection (setuid or \
                 non-dumpable programs such as ssh-agent or keyring daemons). One of them probably holds it."
            ),
            _ => "No visible process holds this socket. The process may have exited between reads, or live in \
                  another PID namespace (a container)."
                .into(),
        }
    }
}

pub fn hidden_label(reason: &str) -> &'static str {
    match reason {
        "closed" => "Closed before attribution",
        "other-user" => "Hidden: other user",
        "protected" => "Hidden: protected process",
        _ => "Unattributed",
    }
}

/// Decode "0100007F:0277" into ("127.0.0.1", 631). The kernel prints the address as the
/// in-memory 32-bit words in hex (CPU byte order); the port is in host order.
pub fn decode_address(field: &str, little_endian: bool) -> Option<(String, u32)> {
    let (hexip, hexport) = field.split_once(':')?;
    let port = u32::from_str_radix(hexport, 16).ok()?;
    let word = |s: &str| -> Option<[u8; 4]> {
        let v = u32::from_str_radix(s, 16).ok()?;
        Some(if little_endian { v.to_le_bytes() } else { v.to_be_bytes() })
    };
    let ip: IpAddr = match hexip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(hexip)?)),
        32 => {
            let mut raw = [0u8; 16];
            for i in 0..4 {
                raw[i * 4..i * 4 + 4].copy_from_slice(&word(hexip.get(i * 8..i * 8 + 8)?)?);
            }
            let v6 = Ipv6Addr::from(raw);
            // A dual-stack socket talking IPv4.
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => return None,
    };
    Some((ip.to_string(), port))
}

/// Parse one /proc/net/{tcp,tcp6,udp,udp6} file. Malformed lines are skipped.
pub fn parse_table(text: &str, table: &str) -> Vec<Socket> {
    let proto = if table.starts_with("tcp") { "tcp" } else { "udp" };
    let little = cfg!(target_endian = "little");
    let mut out = vec![];
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || !f[0].ends_with(':') {
            continue;
        }
        let parsed = (|| {
            let (lip, lport) = decode_address(f[1], little)?;
            let (rip, rport) = decode_address(f[2], little)?;
            let st = u32::from_str_radix(f[3], 16).ok()?;
            let (timer, when) = f[5].split_once(':').unwrap_or((f[5], ""));
            let uid: u32 = f[7].parse().ok()?;
            let inode: u64 = f[9].parse().ok()?;
            let timer = u32::from_str_radix(timer, 16).ok()?;
            let when = u64::from_str_radix(when, 16).ok()?;
            Some((lip, lport, rip, rport, st, timer, when, uid, inode))
        })();
        let Some((lip, lport, rip, rport, st, timer, when, uid, inode)) = parsed else { continue };
        let state = if proto == "tcp" { tcp_state(st) } else { udp_state(st) }
            .map_or_else(|| format!("0x{st:02X}"), String::from);
        let kind = if (proto == "tcp" && state == "LISTEN") || (rport == 0 && scope_of(&rip) == "unspecified") {
            "listen"
        } else {
            "connection"
        };
        let closed_ago = (state == "TIME_WAIT" && timer == 3)
            .then(|| TIME_WAIT_SECONDS - (when as f64 / CLK_TCK).min(TIME_WAIT_SECONDS));
        out.push(Socket {
            table: table.into(),
            proto: proto.into(),
            local_ip: lip,
            local_port: lport,
            remote_ip: rip,
            remote_port: rport,
            state,
            uid,
            inode,
            kind: kind.into(),
            direction: "out".into(),
            closed_ago,
            bytes_sent: None,
            bytes_recv: None,
            pid: None,
            pids: vec![],
            program: None,
            hidden: None,
        });
    }
    out
}

const INTERPRETERS: [&str; 16] = [
    "python", "perl", "ruby", "node", "nodejs", "java", "php", "lua", "bash", "sh", "dash", "zsh", "ksh", "fish",
    "pwsh", "deno",
];

/// `^(python|perl|...|bun)[\d.]*$`
fn is_interpreter(base: &str) -> bool {
    let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.contains(&stem) || stem == "bun"
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// A stable key for "which program" plus a short display name. Interpreters are keyed
/// by the script they run, so two Python scripts are two programs. A deleted executable
/// keeps its path; the deletion is reported separately.
pub fn program_identity(exe: Option<&str>, cmdline: &[String], comm: &str) -> (String, String) {
    let exe = exe.unwrap_or("");
    let stripped = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    let path = if !stripped.is_empty() { stripped } else { cmdline.first().map_or("", String::as_str) };
    if path.is_empty() {
        // Kernel threads have neither; their names may contain '/'.
        return (format!("[{comm}]"), format!("[{comm}]"));
    }
    let base = basename(path);
    let mut target: Option<String> = None;
    if is_interpreter(base) {
        let args = cmdline.get(1..).unwrap_or(&[]);
        for (i, arg) in args.iter().enumerate() {
            if arg == "-m" || arg == "-jar" {
                target = args.get(i + 1).map(|n| format!("{arg} {n}"));
                break;
            }
            if arg == "-c" {
                break; // inline code: keep the interpreter as the program
            }
            if !arg.starts_with('-') {
                target = Some(arg.clone());
                break;
            }
        }
    }
    match target {
        Some(t) => {
            let name = if t.starts_with('-') {
                t.split_whitespace().last().unwrap_or("").to_string()
            } else {
                basename(&t).to_string()
            };
            (format!("{path} {t}"), format!("{name} ({base})"))
        }
        None => (path.to_string(), base.to_string()),
    }
}

/// The hidepid= mount option of /proc, if set (hardened distros use it).
pub fn hidepid_option(mountinfo: &Path) -> Option<String> {
    let text = std::fs::read_to_string(mountinfo).ok()?;
    for line in text.lines() {
        let Some((left, right)) = line.split_once(" - ") else { continue };
        let fstype = right.split_whitespace().next();
        let mount_point = left.split_whitespace().nth(4);
        if fstype == Some("proc") && mount_point == Some("/proc") {
            let opts = right.split_whitespace().last().unwrap_or("");
            if let Some(v) = opts.split(',').find_map(|o| o.strip_prefix("hidepid=")) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Copy the synthetic /proc fixture into `dst`, creating its symlinks from links.txt
/// (the fixture lists them so it survives any checkout). For tests.
pub fn materialise_fixture(src: &Path, dst: &Path) -> io::Result<HashSet<u32>> {
    fn copy_dir(src: &Path, dst: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for e in std::fs::read_dir(src)? {
            let e = e?;
            let to = dst.join(e.file_name());
            if e.file_type()?.is_dir() {
                copy_dir(&e.path(), &to)?;
            } else {
                std::fs::copy(e.path(), to)?;
            }
        }
        Ok(())
    }
    copy_dir(src, dst)?;
    for line in std::fs::read_to_string(dst.join("links.txt"))?.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((path, target)) = line.split_once(" -> ") {
            let link = dst.join(path);
            if let Some(dir) = link.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::os::unix::fs::symlink(target, link)?;
        }
    }
    let blocked = std::fs::read_to_string(dst.join("unreadable.txt"))?
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect::<BTreeSet<u32>>();
    Ok(blocked.into_iter().collect())
}
