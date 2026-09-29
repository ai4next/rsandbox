//! seccomp-bpf syscall filter.
//!
//! The filter is a *denylist*, not an allowlist: a workload may make any syscall
//! except the ones below. That mirrors what container runtimes ship by default,
//! and it is the only sane default when the workload is arbitrary generated code
//! — a strict allowlist one syscall short turns a working agent into a
//! mysteriously crashing one, and the resulting pressure to widen it erodes the
//! sandbox anyway.
//!
//! The denied set is exactly what would let a process escape or reshape the
//! sandbox it is already inside. Denied calls return `EPERM` rather than killing
//! the process, so a workload that tries to `mount` fails visibly instead of
//! vanishing.

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

/// Syscalls denied to every sandboxed workload.
#[allow(unused_mut)]
fn denied() -> Vec<(&'static str, libc::c_long)> {
    let mut syscalls: Vec<(&'static str, libc::c_long)> = vec![
        // Kernel, module and firmware manipulation.
        ("init_module", libc::SYS_init_module),
        ("finit_module", libc::SYS_finit_module),
        ("delete_module", libc::SYS_delete_module),
        ("kexec_load", libc::SYS_kexec_load),
        ("kexec_file_load", libc::SYS_kexec_file_load),
        ("reboot", libc::SYS_reboot),
        ("swapon", libc::SYS_swapon),
        ("swapoff", libc::SYS_swapoff),
        ("acct", libc::SYS_acct),
        // Reshaping or escaping the namespace tree. The sandbox is already set
        // up; the workload has no business redoing it.
        ("mount", libc::SYS_mount),
        ("umount2", libc::SYS_umount2),
        ("pivot_root", libc::SYS_pivot_root),
        ("chroot", libc::SYS_chroot),
        ("setns", libc::SYS_setns),
        ("unshare", libc::SYS_unshare),
        ("move_mount", libc::SYS_move_mount),
        ("open_tree", libc::SYS_open_tree),
        ("fsopen", libc::SYS_fsopen),
        ("fsconfig", libc::SYS_fsconfig),
        ("fsmount", libc::SYS_fsmount),
        ("fspick", libc::SYS_fspick),
        ("mount_setattr", libc::SYS_mount_setattr),
        // Cross-process inspection and control.
        ("ptrace", libc::SYS_ptrace),
        ("process_vm_readv", libc::SYS_process_vm_readv),
        ("process_vm_writev", libc::SYS_process_vm_writev),
        ("pidfd_getfd", libc::SYS_pidfd_getfd),
        ("kcmp", libc::SYS_kcmp),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("bpf", libc::SYS_bpf),
        ("userfaultfd", libc::SYS_userfaultfd),
        // Kernel keyring and audit surfaces.
        ("add_key", libc::SYS_add_key),
        ("request_key", libc::SYS_request_key),
        ("keyctl", libc::SYS_keyctl),
        ("syslog", libc::SYS_syslog),
        // Host configuration.
        ("settimeofday", libc::SYS_settimeofday),
        ("clock_settime", libc::SYS_clock_settime),
        ("clock_adjtime", libc::SYS_clock_adjtime),
        ("adjtimex", libc::SYS_adjtimex),
        ("sethostname", libc::SYS_sethostname),
        ("setdomainname", libc::SYS_setdomainname),
        ("quotactl", libc::SYS_quotactl),
        ("nfsservctl", libc::SYS_nfsservctl),
        ("lookup_dcookie", libc::SYS_lookup_dcookie),
        ("fanotify_init", libc::SYS_fanotify_init),
        ("name_to_handle_at", libc::SYS_name_to_handle_at),
        ("open_by_handle_at", libc::SYS_open_by_handle_at),
    ];
    // Port I/O exists only on x86.
    #[cfg(target_arch = "x86_64")]
    {
        syscalls.push(("iopl", libc::SYS_iopl));
        syscalls.push(("ioperm", libc::SYS_ioperm));
    }
    syscalls
}

/// Compile the default denylist filter.
///
/// Compilation happens in the supervisor, never in the forked child, so the
/// child only has to install an already-built program.
// `c_long` is already `i64` on the 64-bit targets we ship, but the conversion is
// what keeps this correct on a 32-bit one, so it stays.
#[allow(clippy::useless_conversion)]
pub fn default_filter() -> Result<BpfProgram, String> {
    let rules: BTreeMap<i64, Vec<SeccompRule>> = denied()
        .into_iter()
        // An empty rule vector matches on the syscall number alone.
        .map(|(_, number)| (i64::from(number), Vec::new()))
        .collect();

    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|err| format!("unsupported architecture: {err}"))?;

    let filter = SeccompFilter::new(
        rules,
        // Anything not named above is allowed; anything named above gets EPERM.
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|err| format!("seccomp filter: {err}"))?;

    BpfProgram::try_from(filter).map_err(|err| format!("seccomp compile: {err}"))
}

/// Install `program` on the calling thread.
///
/// Must run in the sandboxed child, immediately before `exec`, because a seccomp
/// filter applies to the process that installs it. It is a plain syscall
/// sequence and therefore safe in the forked child; failures are reported as a
/// bare errno because formatting an error would allocate.
pub fn install(program: &BpfProgram) -> std::io::Result<()> {
    seccompiler::apply_filter(program).map_err(|_| std::io::Error::from_raw_os_error(libc::EPERM))
}
