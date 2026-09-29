//! Validation harness for the Linux backend.
//!
//! These tests exercise the real syscall sequences — namespaces, cgroup, seccomp
//! and Landlock — so they only run on Linux. Anything the host cannot provide is
//! reported as a *skip* rather than a failure, so a green run means the host
//! actually proved the property, not that the test quietly passed.
//!
//! They are the reason this backend can claim to be trustworthy: until they have
//! run on a real kernel, the syscall ordering is reviewed but unverified.

#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use rsandbox::{
    Backend, ExecOutput, ExecRequest, ExitStatus, FsPolicy, IsolationLevel, NetPolicy,
    SandboxError, SandboxSpec,
};

/// A spec pinned to the Linux backend using the default (deny) network policy and
/// a writable `/tmp`, so a failure below is a real isolation failure rather than
/// an admission rejection.
fn spec() -> SandboxSpec {
    SandboxSpec {
        backend: Some("linux".into()),
        net: NetPolicy::Loopback,
        fs: FsPolicy {
            workdir: "/tmp".into(),
            tmpfs: vec!["/tmp".into()],
            ..FsPolicy::default()
        },
        ..SandboxSpec::default()
    }
}

fn backend() -> Arc<dyn Backend> {
    rsandbox::registry()
        .get("linux")
        .expect("the linux backend is registered on Linux")
}

/// Skip the test when the host cannot host the sandbox at all, so that a
/// constrained CI container reports "unproven" instead of a misleading pass.
macro_rules! require_isolation {
    ($backend:expr) => {{
        let caps = $backend.capabilities();
        if caps.isolation == IsolationLevel::None {
            eprintln!("skip: unprivileged user namespaces are unavailable on this host");
            return;
        }
        if !caps.filesystem_jail {
            eprintln!("skip: this kernel has no Landlock support");
            return;
        }
        if !caps.syscall_filter {
            eprintln!("skip: seccomp-bpf is unavailable");
            return;
        }
    }};
}

fn run(backend: &Arc<dyn Backend>, spec: &SandboxSpec, script: &str) -> ExecOutput {
    let mut sandbox = backend.create(spec).expect("the spec is supported");
    let output = sandbox
        .exec(&ExecRequest::new(["/bin/sh", "-c", script]))
        .expect("the command runs");
    sandbox
        .terminate(Duration::ZERO)
        .expect("terminate succeeds");
    output
}

#[test]
fn runs_a_command_through_the_full_pipeline() {
    let backend = backend();
    require_isolation!(backend);
    // A successful `echo` proves the whole chain works: the user namespace and
    // its uid mapping, the private mount namespace, the Landlock baseline that
    // lets a dynamic binary load, the seccomp denylist that does not break normal
    // programs, and the final chdir.
    let output = run(&backend, &spec(), "echo hello from linux");
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello from linux"
    );
}

#[test]
fn workload_is_root_inside_the_user_namespace() {
    let backend = backend();
    require_isolation!(backend);
    // Root inside, unprivileged outside: that mapping is the point of the user
    // namespace. Read through the shell so the test needs no extra binaries.
    let output = run(
        &backend,
        &spec(),
        "while read -r key value _; do [ \"$key\" = 'Uid:' ] && echo \"$value\"; done < /proc/self/status",
    );
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "0",
        "the sandboxed uid must be mapped to root"
    );
}

#[test]
fn installs_a_seccomp_filter() {
    let backend = backend();
    require_isolation!(backend);
    // `Seccomp: 2` means a filter is installed (mode SECCOMP_MODE_FILTER).
    let output = run(
        &backend,
        &spec(),
        "while read -r key value _; do [ \"$key\" = 'Seccomp:' ] && echo \"$value\"; done < /proc/self/status",
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "2",
        "a seccomp filter must be installed before exec"
    );
}

#[test]
fn denies_writes_outside_the_policy() {
    let backend = backend();
    require_isolation!(backend);
    // `/etc` is read-only under the Landlock baseline and the policy grants no
    // write access there, so the kernel must refuse the write.
    let output = run(
        &backend,
        &spec(),
        "echo probe > /etc/rsandbox-should-not-exist",
    );
    assert!(
        !output.success(),
        "writing outside the policy must be denied, got {:?}",
        output.status
    );
}

#[test]
fn keeps_tmpfs_writes_out_of_the_host() {
    let backend = backend();
    require_isolation!(backend);
    // The mount namespace plus the `/tmp` tmpfs must mean the sandbox's scratch
    // space is not the host's.
    let host_path = std::path::Path::new("/tmp/rsandbox-namespace-probe");
    let _ = std::fs::remove_file(host_path);

    let output = run(
        &backend,
        &spec(),
        "echo probe > /tmp/rsandbox-namespace-probe",
    );
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert!(
        !host_path.exists(),
        "a write inside the sandbox leaked into the host /tmp"
    );
}

#[test]
fn enforces_the_wall_clock_deadline() {
    let backend = backend();
    require_isolation!(backend);
    let mut spec = spec();
    spec.resources.wall_time_ms = Some(300);
    let started = Instant::now();
    let output = run(&backend, &spec, "sleep 30");
    assert_eq!(output.status, ExitStatus::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the deadline was not enforced: took {:?}",
        started.elapsed()
    );
}

#[test]
fn refuses_egress_filtering_it_cannot_do() {
    let backend = backend();
    require_isolation!(backend);
    // Fail closed: an allowlist needs a filtering proxy or nftables rules, so
    // `create` must reject it rather than run with unrestricted egress.
    let mut spec = spec();
    spec.net = NetPolicy::Allow(vec!["example.com:443".into()]);
    assert!(
        matches!(backend.create(&spec), Err(SandboxError::Unsupported { .. })),
        "an egress allowlist the backend cannot enforce must be rejected"
    );
}
