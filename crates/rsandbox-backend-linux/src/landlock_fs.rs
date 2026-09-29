//! Landlock filesystem confinement.
//!
//! Landlock is what makes this backend useful without a root filesystem image:
//! it grants exactly the filesystem access the policy names, on top of the
//! minimum a dynamically linked program needs to start at all. Everything else —
//! `$HOME`, `/etc` beyond the loader configuration, other agents' scratch space —
//! is denied, and denied by the kernel rather than by convention.
//!
//! The ruleset is built in the supervisor and installed in the child with
//! `landlock_restrict_self`, so the forked child performs no allocation.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
    path_beneath_rules,
};
use rsandbox_core::FsPolicy;

/// Paths a dynamically linked program needs merely to start.
///
/// Deliberately read-only and narrow. This is a policy default rather than a
/// kernel requirement, and it is the first thing that should become
/// configurable on `SandboxSpec`.
const RUNTIME_READ: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    // Without a PID namespace `/proc` still exposes host processes, so only the
    // self entries are granted. This is the mitigation for that gap.
    "/proc/self",
    "/proc/thread-self",
    "/sys/devices/system/cpu",
];

/// Translate a probed Landlock ABI version into the crate's enum.
pub fn abi(version: u8) -> Option<ABI> {
    match version {
        0 => None,
        1 => Some(ABI::V1),
        2 => Some(ABI::V2),
        3 => Some(ABI::V3),
        4 => Some(ABI::V4),
        5 => Some(ABI::V5),
        // Newer kernels are a superset of the newest ABI this crate knows.
        _ => Some(ABI::V6),
    }
}

/// Build the ruleset that confines the workload, returning the descriptor to
/// install in the child.
pub fn build(policy: &FsPolicy, abi: ABI) -> Result<OwnedFd, String> {
    let created = Ruleset::default()
        // A kernel that cannot enforce what we asked for must fail here rather
        // than silently run without a filesystem jail.
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|err| format!("landlock handle_access: {err}"))?
        .create()
        .map_err(|err| format!("landlock create: {err}"))?;

    let read: Vec<PathBuf> = RUNTIME_READ
        .iter()
        .map(PathBuf::from)
        .chain(policy.read_allow.iter().cloned())
        .collect();
    let created = created
        .add_rules(path_beneath_rules(&read, AccessFs::from_read(abi)))
        .map_err(|err| format!("landlock read rules: {err}"))?;

    // Writable paths need every right the ABI offers, not just `WriteFile`:
    // creating, renaming and removing entries all have their own bit.
    let write: Vec<PathBuf> = policy
        .write_allow
        .iter()
        .cloned()
        .chain(policy.tmpfs.iter().cloned())
        .collect();
    let created = if write.is_empty() {
        created
    } else {
        created
            .add_rules(path_beneath_rules(&write, AccessFs::from_all(abi)))
            .map_err(|err| format!("landlock write rules: {err}"))?
    };

    let fd: Option<OwnedFd> = created.into();
    fd.ok_or_else(|| "landlock returned no ruleset descriptor".to_string())
}
