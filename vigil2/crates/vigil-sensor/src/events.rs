//! Process events from the kernel's proc connector (netlink): every exec, fork and exit as
//! it happens, so a program that runs for 50 ms is still seen. This is the first fallback
//! below the eBPF sensor (docs/RUST_REWRITE.md section 4).
//!
//! Needs CAP_NET_ADMIN (the installed service has it) and the initial PID namespace; inside
//! a container the kernel sends nothing, and the daemon keeps polling /proc as before.
//! Only pids and exit codes arrive here; everything else is read from /proc at once.

use neli::{
    connector::{CnMsg, CnMsgBuilder, ProcEvent, ProcEventHeader},
    consts::{
        connector::{CnMsgIdx, CnMsgVal, ProcCnMcastOp},
        nl::{NlmF, Nlmsg},
        socket::NlFamily,
    },
    nl::{NlPayload, NlmsghdrBuilder},
    socket::synchronous::NlSocketHandle,
    utils::Groups,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A process (thread-group leader) started a new program.
    Exec { pid: u32 },
    /// A new process (not a thread) was forked from `parent`.
    Fork { parent: u32, child: u32 },
    /// A process ended.
    Exit { pid: u32, code: u32 },
}

pub struct ProcEvents {
    sock: NlSocketHandle,
}

impl ProcEvents {
    /// Subscribe to the proc connector. Fails without CAP_NET_ADMIN.
    pub fn open() -> Result<ProcEvents, String> {
        // Port id 0: the kernel picks a free one (two listeners in one process do not clash).
        let sock = NlSocketHandle::connect(NlFamily::Connector, None, Groups::new_bitmask(CnMsgIdx::Proc.into()))
            .map_err(|e| format!("cannot open the proc connector: {e}"))?;
        let pid = 0;
        let msg = CnMsgBuilder::default()
            .idx(CnMsgIdx::Proc)
            .val(CnMsgVal::Proc)
            .payload(ProcCnMcastOp::Listen)
            .build()
            .map_err(|e| e.to_string())?;
        let subscribe = NlmsghdrBuilder::default()
            .nl_type(Nlmsg::Done)
            .nl_flags(NlmF::empty())
            .nl_pid(pid)
            .nl_payload(NlPayload::Payload(msg))
            .build()
            .map_err(|e| e.to_string())?;
        sock.send(&subscribe).map_err(|e| format!("cannot subscribe to process events: {e}"))?;
        Ok(ProcEvents { sock })
    }

    /// Wait for the next batch of events (blocks).
    pub fn next(&self) -> Result<Vec<Event>, String> {
        let (msgs, _) = self.sock.recv::<Nlmsg, CnMsg<ProcEventHeader>>().map_err(|e| e.to_string())?;
        let mut out = vec![];
        for m in msgs {
            let Ok(m) = m else { continue };
            let Some(p) = m.get_payload() else { continue };
            let ev = match p.payload().event {
                ProcEvent::Exec { process_pid, process_tgid } if process_pid == process_tgid => {
                    Event::Exec { pid: process_tgid as u32 }
                }
                ProcEvent::Fork { parent_tgid, child_pid, child_tgid, .. } if child_pid == child_tgid => {
                    Event::Fork { parent: parent_tgid as u32, child: child_tgid as u32 }
                }
                ProcEvent::Exit { process_pid, process_tgid, exit_code, .. } if process_pid == process_tgid => {
                    Event::Exit { pid: process_tgid as u32, code: exit_code }
                }
                _ => continue,
            };
            out.push(ev);
        }
        Ok(out)
    }
}
