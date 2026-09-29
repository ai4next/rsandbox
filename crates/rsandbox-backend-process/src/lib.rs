//! Portable, process-level backend for `rsandbox`.
//!
//! This is the reference implementation of [`rsandbox_core::Backend`] and the
//! weakest useful isolation level. It establishes **no kernel boundary**: the
//! workload shares the host filesystem and network namespace. What it does give
//! you is deterministic resource budgets and lifetime control:
//!
//! * a scrubbed environment (host secrets never leak by default),
//! * `RLIMIT_*` budgets for CPU time, address space, fds, file size and pids,
//! * a wall-clock deadline enforced by killing the whole process group,
//! * bounded output capture so a chatty workload cannot exhaust the supervisor.
//!
//! It exists for two reasons: it runs everywhere (including macOS dev machines)
//! and it proves the [`rsandbox_core::Sandbox`] contract that stronger backends
//! implement. Anything needing real isolation must use `rsandbox-backend-linux`
//! (or a future WASM/microVM backend); this backend refuses specs it cannot
//! honour rather than silently downgrading them.

#[cfg(unix)]
mod sandbox;

#[cfg(unix)]
pub use sandbox::{BACKEND_NAME, ProcessBackend};

/// Register this backend into `registry`. No-op on non-Unix hosts.
pub fn register(registry: &mut rsandbox_core::Registry) {
    #[cfg(unix)]
    registry.register(std::sync::Arc::new(ProcessBackend::new()));
    #[cfg(not(unix))]
    let _ = registry;
}
