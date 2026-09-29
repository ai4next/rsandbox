//! Linux-native isolation backend for `rsandbox`.
//!
//! This is the backend that delivers the "secure" half of the promise. A
//! sandboxed command runs inside
//!
//! * a **user namespace** with a single uid/gid mapping, so an unprivileged
//!   supervisor can create the other namespaces and the workload holds root only
//!   *inside* the sandbox,
//! * **mount, IPC, UTS and (optionally) network namespaces**, so it cannot see
//!   host mounts, SysV IPC objects, the host hostname or the host network,
//! * a **cgroup v2** subtree, so CPU weight, memory and pid budgets apply to the
//!   whole process tree and `terminate` can kill that tree atomically,
//! * a **seccomp-bpf** filter denying the syscalls used to escape or reshape a
//!   sandbox (`mount`, `unshare`, `setns`, `ptrace`, `bpf`, module loading, …),
//! * a **Landlock** ruleset granting read access only to the runtime and the
//!   paths the policy names, and write access only to declared scratch space,
//! * **`RLIMIT_*`** budgets as a second, per-process line of defence.
//!
//! Everything is arranged so that an unprivileged process can build all of it:
//! no root, no setuid helper, no daemon with elevated privileges.
//!
//! # Known gaps
//!
//! Deliberate, and all of them fail closed — `create` rejects a spec that needs
//! them rather than quietly running with less isolation:
//!
//! * **No PID namespace.** `std::process::Command` blocks in the supervisor
//!   until the child `exec`s, so the usual "fork again to become pid 1" trick
//!   would stall `spawn` for the workload's whole lifetime. Closing this needs a
//!   hand-rolled fork/exec or a small init helper. In the meantime Landlock
//!   grants only `/proc/self` and `/proc/thread-self`, so host processes are not
//!   readable.
//! * **No root filesystem images** (`fs.rootfs`, `fs.mounts`).
//! * **No egress filtering** (`NetPolicy::Allow`): needs a proxy or nftables.
//! * **No snapshot/fork** for warm starts.
//!
//! # Validation status
//!
//! Compile-checked for `x86_64-unknown-linux-gnu`. The syscall sequences have not
//! yet been exercised against a live kernel, so treat the first Linux CI run as
//! the point where they become trustworthy.

#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod landlock_fs;
#[cfg(target_os = "linux")]
mod probe;
#[cfg(target_os = "linux")]
mod sandbox;
#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(target_os = "linux")]
pub use probe::KernelFeatures;
#[cfg(target_os = "linux")]
pub use sandbox::{BACKEND_NAME, LinuxBackend};

/// Register this backend into `registry`. No-op on non-Linux hosts, so that the
/// umbrella crate can register every backend unconditionally.
pub fn register(registry: &mut rsandbox_core::Registry) {
    #[cfg(target_os = "linux")]
    registry.register(std::sync::Arc::new(LinuxBackend::new()));
    #[cfg(not(target_os = "linux"))]
    let _ = registry;
}
