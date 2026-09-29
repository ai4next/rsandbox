//! Child lifetime control: wait for a workload, and take down the whole tree it
//! spawned when the deadline expires.

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus as ProcessExitStatus};
use std::time::{Duration, Instant};

use rsandbox_core::{ExitStatus, ResourceLimits};

use crate::POLL_INTERVAL;

pub enum Wait {
    Exited(ProcessExitStatus),
    TimedOut,
}

/// Wait for `child`, invoking `on_timeout` once `timeout` elapses.
///
/// The kill itself is the caller's business because it is backend-specific: the
/// portable backend kills a process group, while the Linux backend also kills
/// the sandbox's cgroup, which is the only thing that reliably reaches processes
/// that changed their own process group.
pub fn wait_with_deadline(
    child: &mut Child,
    timeout: Option<Duration>,
    started: Instant,
    mut on_timeout: impl FnMut(),
) -> io::Result<Wait> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Wait::Exited(status));
        }
        if let Some(deadline) = timeout {
            if started.elapsed() >= deadline {
                on_timeout();
                // Reap so the child does not linger as a zombie.
                let _ = child.wait();
                return Ok(Wait::TimedOut);
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Kill the whole process group led by `pgid`.
pub fn kill_group(pgid: i32) {
    // SAFETY: a negative pid addresses the process group. The group is one we
    // created ourselves and cannot have been recycled while its leader is still
    // our unreaped child.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

/// Map a fatal signal onto a budget-exhaustion status where the sandbox's own
/// limits explain the death, so callers can tell "OOM/CPU killed" apart from
/// "the workload crashed".
pub fn classify_signal(signal: i32, limits: &ResourceLimits) -> ExitStatus {
    // SIGXCPU is the kernel reporting that the CPU budget is spent. A SIGKILL is
    // ambiguous, but when a memory budget was declared the OOM killer is the
    // likely author, which tells the caller far more than a bare signal number.
    if signal == libc::SIGXCPU || (signal == libc::SIGKILL && limits.memory_bytes.is_some()) {
        ExitStatus::Killed
    } else {
        ExitStatus::Signaled(signal)
    }
}

/// Classify a reaped process into an [`ExitStatus`].
pub fn classify(status: ProcessExitStatus, limits: &ResourceLimits) -> ExitStatus {
    match status.signal() {
        Some(signal) => classify_signal(signal, limits),
        None => ExitStatus::Exited(status.code().unwrap_or(-1)),
    }
}
