//! `RLIMIT_*` budgets.
//!
//! Limits are only ever *lowered*, so applying them needs no privilege. A host
//! hard limit below what the spec asks for surfaces as an error instead of being
//! silently clamped: a sandbox must not run with a different budget than the
//! caller declared.
//!
//! These are per-process limits. A workload's descendants inherit them, but they
//! are not tree-wide accounting — that is what the Linux backend's cgroup
//! support adds on top.

use std::io;

use rsandbox_core::ResourceLimits;

/// `setrlimit`'s resource parameter is `u32` on Linux and `i32` on the BSDs and
/// macOS, and the `RLIMIT_*` constants follow suit. Alias it so the calls below
/// stay identical on both.
#[cfg(target_os = "linux")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type RlimitResource = libc::c_int;

/// Apply every `RLIMIT_*` budget the spec declares.
///
/// Callers that run this in a forked child (before `exec`) must be aware that
/// only async-signal-safe operations are permitted there; this function performs
/// nothing but `setrlimit` syscalls, so it qualifies.
pub fn apply_limits(limits: &ResourceLimits) -> io::Result<()> {
    if let Some(ms) = limits.cpu_time_ms {
        // RLIMIT_CPU is whole seconds; round up so a sub-second budget still bites.
        let secs = ms.div_ceil(1000).max(1);
        set_limit(libc::RLIMIT_CPU, secs, secs)?;
    }
    if let Some(bytes) = limits.memory_bytes {
        set_limit(libc::RLIMIT_AS, bytes, bytes)?;
    }
    if let Some(max) = limits.open_files_max {
        set_limit(libc::RLIMIT_NOFILE, max, max)?;
    }
    if let Some(bytes) = limits.file_size_bytes {
        set_limit(libc::RLIMIT_FSIZE, bytes, bytes)?;
    }
    if let Some(max) = limits.pids_max {
        set_limit(libc::RLIMIT_NPROC, u64::from(max), u64::from(max))?;
    }
    Ok(())
}

fn set_limit(resource: RlimitResource, soft: u64, hard: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // SAFETY: `limit` is a well-formed `rlimit` for `resource`.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
