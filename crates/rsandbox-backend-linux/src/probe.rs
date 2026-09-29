//! Runtime detection of the kernel features this backend relies on.
//!
//! Capabilities are probed at runtime rather than assumed from the compile
//! target. A container without a writable cgroup subtree, or a kernel with
//! unprivileged user namespaces disabled, must be reported honestly so that
//! `create` refuses a spec instead of running it with less isolation than the
//! caller was promised.

use std::ffi::CString;
use std::path::Path;

/// What the running kernel allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelFeatures {
    /// Unprivileged user namespaces can be created.
    pub user_namespaces: bool,
    /// A writable cgroup v2 subtree is available.
    pub cgroup_v2: bool,
    /// Highest supported Landlock ABI, or 0 when the kernel has no Landlock.
    pub landlock_abi: u8,
    /// seccomp-bpf is available.
    pub seccomp: bool,
}

impl KernelFeatures {
    pub fn has_landlock(&self) -> bool {
        self.landlock_abi > 0
    }
}

pub fn detect() -> KernelFeatures {
    KernelFeatures {
        user_namespaces: user_namespaces_available(),
        cgroup_v2: cgroup_v2_available(),
        landlock_abi: landlock_abi(),
        seccomp: seccomp_available(),
    }
}

/// Root can always create a user namespace; an unprivileged process needs the
/// global limit to be non-zero and, on Debian-derived kernels, the extra switch
/// to be enabled.
fn user_namespaces_available() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    // A zero limit means the feature is off. A missing file tells us nothing, so
    // we stay optimistic and let `unshare` fail closed at `exec` time.
    if let Some(0) = read_u64("/proc/sys/user/max_user_namespaces") {
        return false;
    }
    if let Some(0) = read_u64("/proc/sys/kernel/unprivileged_userns_clone") {
        return false;
    }
    true
}

fn cgroup_v2_available() -> bool {
    // The unified hierarchy advertises its controllers through this file, and a
    // delegated subtree is writable by us — which is what creating a child
    // cgroup requires.
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return false;
    }
    let Ok(root) = CString::new("/sys/fs/cgroup") else {
        return false;
    };
    // SAFETY: `root` is a valid NUL-terminated path.
    unsafe { libc::access(root.as_ptr(), libc::W_OK) == 0 }
}

/// `LANDLOCK_CREATE_RULESET_VERSION` from `linux/landlock.h`. With this flag the
/// kernel ignores the other arguments and returns the supported ABI version.
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;

fn landlock_abi() -> u8 {
    // SAFETY: with VERSION set the kernel dereferences none of the arguments.
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0 as libc::c_long,
            libc::c_long::from(LANDLOCK_CREATE_RULESET_VERSION),
        )
    };
    u8::try_from(version).unwrap_or(0)
}

fn seccomp_available() -> bool {
    // `PR_GET_SECCOMP` reports the current mode and fails with EINVAL on kernels
    // built without seccomp: the cheapest reliable probe.
    // SAFETY: `prctl` with `PR_GET_SECCOMP` dereferences no pointer arguments.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
}

fn read_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}
