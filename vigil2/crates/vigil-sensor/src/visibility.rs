//! "What Vigil can and cannot see": which source feeds each signal on this machine,
//! what it misses, and what would give more. Every line is a fact read from the system
//! or a statement about what this version has built, never a guess.

use std::path::Path;
use vigil_model::host::SourceStatus;

/// Facts about the kernel that decide which sensors can work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelFacts {
    pub release: String,
    pub btf: bool,
    /// kernel.unprivileged_bpf_disabled (0, 1 or 2), if readable.
    pub unprivileged_bpf_disabled: Option<u8>,
    /// The active lockdown mode ("none", "integrity", "confidentiality"), if any.
    pub lockdown: Option<String>,
    /// LSMs in the boot order; "bpf" among them enables BPF LSM hooks.
    pub lsms: Vec<String>,
}

pub fn kernel_facts(root: &Path) -> KernelFacts {
    let read = |p: &str| std::fs::read_to_string(root.join(p)).ok().map(|s| s.trim().to_string());
    KernelFacts {
        release: read("proc/sys/kernel/osrelease").unwrap_or_default(),
        btf: root.join("sys/kernel/btf/vmlinux").exists(),
        unprivileged_bpf_disabled: read("proc/sys/kernel/unprivileged_bpf_disabled").and_then(|s| s.parse().ok()),
        // "[none] integrity confidentiality": the bracketed word is active.
        lockdown: read("sys/kernel/security/lockdown").and_then(|s| {
            s.split_whitespace().find(|w| w.starts_with('[')).map(|w| w.trim_matches(['[', ']']).to_string())
        }),
        lsms: read("sys/kernel/security/lsm").map(|s| s.split(',').map(String::from).collect()).unwrap_or_default(),
    }
}

fn status(signal: &str, source: &str, live: bool, note: String) -> SourceStatus {
    SourceStatus { signal: signal.into(), source: source.into(), live, note, dropped: 0 }
}

/// The sources this version uses, with honest notes. `can_ptrace` says whether the
/// daemon may read other users' /proc/<pid>/fd (CAP_SYS_PTRACE or root).
pub fn sources(k: &KernelFacts, can_ptrace: bool, poll_ms: u64) -> Vec<SourceStatus> {
    let secs = poll_ms as f64 / 1000.0;
    let reach = if can_ptrace {
        "every user's processes".to_string()
    } else {
        "only processes of the user the daemon runs as; others show as hidden".to_string()
    };
    let ebpf_hint = if !k.btf {
        "This kernel has no BTF (/sys/kernel/btf/vmlinux), which the eBPF sensor needs.".to_string()
    } else if k.lockdown.as_deref() == Some("confidentiality") {
        "Kernel lockdown is in confidentiality mode, which blocks the eBPF sensor; the event fallbacks still work."
            .to_string()
    } else {
        "This kernel has BTF, so the eBPF sensor (milestone 3) should be able to run here.".to_string()
    };
    vec![
        status(
            "processes",
            "proc-poll",
            true,
            format!(
                "Reads /proc every {secs} s: sees {reach}. Programs that start and finish between two reads are \
                 missed; the event sensors in milestone 3 fix that. {ebpf_hint}"
            ),
        ),
        status(
            "connections",
            "proc-poll",
            true,
            format!(
                "Reads /proc/net every {secs} s and matches sockets to processes through /proc/<pid>/fd: sees \
                 {reach}. Short connections between two reads are missed."
            ),
        ),
        status(
            "dns",
            "none",
            false,
            "Not built yet (milestone 3): which program looked up which name. /proc shows addresses only.".into(),
        ),
        status(
            "file-opens",
            "none",
            false,
            "Not built yet (milestone 3): which program opened SSH keys, browser profiles or wallets.".into(),
        ),
        status(
            "autostart",
            "none",
            false,
            "Not built yet (milestone 4): real-time alerts on new autostart entries.".into(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_fake_root() {
        let d = std::env::temp_dir().join(format!("vigil-vis-{}", std::process::id()));
        std::fs::create_dir_all(d.join("proc/sys/kernel")).unwrap();
        std::fs::create_dir_all(d.join("sys/kernel/security")).unwrap();
        std::fs::write(d.join("proc/sys/kernel/unprivileged_bpf_disabled"), "2\n").unwrap();
        std::fs::write(d.join("sys/kernel/security/lockdown"), "none [integrity] confidentiality\n").unwrap();
        std::fs::write(d.join("sys/kernel/security/lsm"), "capability,landlock,yama,bpf\n").unwrap();
        let k = kernel_facts(&d);
        assert_eq!(k.unprivileged_bpf_disabled, Some(2));
        assert_eq!(k.lockdown.as_deref(), Some("integrity"));
        assert!(k.lsms.contains(&"bpf".to_string()));
        assert!(!k.btf);
        let s = sources(&k, false, 2000);
        assert!(s[0].note.contains("only processes of the user"));
        assert!(s[0].note.contains("no BTF"));
        assert!(s.iter().any(|x| !x.live));
        std::fs::remove_dir_all(d).unwrap();
    }
}
