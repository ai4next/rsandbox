//! End-to-end behaviour of the portable backend — the one that runs on every
//! development machine, and the reference for the [`Sandbox`] contract that
//! stronger backends implement.

#![cfg(unix)]

use std::time::{Duration, Instant};

use rsandbox::{ExecOutput, ExecRequest, NetPolicy, Sandbox, SandboxError, SandboxSpec};

/// The portable backend has no network isolation, so it requires an explicit
/// `NetPolicy::Host`; that is itself part of the fail-closed contract.
fn spec() -> SandboxSpec {
    SandboxSpec {
        backend: Some("process".into()),
        net: NetPolicy::Host,
        ..SandboxSpec::default()
    }
}

fn create(spec: &SandboxSpec) -> Box<dyn Sandbox> {
    rsandbox::registry()
        .resolve(spec)
        .expect("the pinned backend is registered")
        .create(spec)
        .expect("the spec is supported")
}

fn exec(spec: &SandboxSpec, argv: &[&str]) -> ExecOutput {
    let mut sandbox = create(spec);
    let output = sandbox
        .exec(&ExecRequest::new(argv.iter().copied()))
        .expect("the command runs");
    sandbox
        .terminate(Duration::ZERO)
        .expect("terminate succeeds");
    output
}

#[test]
fn captures_stdout_and_exit_code() {
    let output = exec(&spec(), &["/bin/echo", "hello sandbox"]);
    assert!(output.success());
    assert_eq!(output.status, rsandbox::ExitStatus::Exited(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello sandbox"
    );
}

#[test]
fn reports_a_non_zero_exit() {
    let output = exec(&spec(), &["/bin/sh", "-c", "exit 7"]);
    assert!(!output.success());
    assert_eq!(output.status.code(), 7);
}

#[test]
fn clears_the_environment() {
    // Only `PATH` is set, so `env` must print exactly that line: nothing of the
    // host environment (tokens, proxies, credentials) may leak in.
    let output = exec(&spec(), &["/usr/bin/env"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PATH="), "expected PATH, got {stdout:?}");
    assert!(!stdout.contains("HOME="), "host HOME leaked: {stdout:?}");
    assert!(!stdout.contains("USER="), "host USER leaked: {stdout:?}");
    assert_eq!(stdout.lines().count(), 1, "unexpected env: {stdout:?}");
}

#[test]
fn forwards_stdin() {
    let mut sandbox = create(&spec());
    let mut request = ExecRequest::new(["/bin/cat"]);
    request.stdin = b"piped in".to_vec();
    let output = sandbox.exec(&request).expect("cat runs");
    assert_eq!(output.stdout, b"piped in");
}

#[test]
fn runs_in_the_requested_workdir() {
    let mut spec = spec();
    spec.fs.workdir = "/usr".into();
    let output = exec(&spec, &["/bin/pwd"]);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "/usr");
}

#[test]
fn enforces_the_wall_clock_deadline() {
    let mut spec = spec();
    spec.resources.wall_time_ms = Some(150);
    let started = Instant::now();
    let output = exec(&spec, &["/bin/sleep", "10"]);
    assert_eq!(output.status, rsandbox::ExitStatus::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the deadline was not enforced: took {:?}",
        started.elapsed()
    );
}

#[test]
fn enforces_the_file_size_budget() {
    let mut spec = spec();
    spec.resources.file_size_bytes = Some(1024);
    // Writing past `RLIMIT_FSIZE` raises SIGXFSZ, whose default action kills the
    // process: the budget has to bite rather than be silently ignored.
    let output = exec(
        &spec,
        &[
            "/bin/sh",
            "-c",
            "dd if=/dev/zero of=/tmp/rsandbox-fsize-test bs=1 count=65536 2>/dev/null",
        ],
    );
    let _ = std::fs::remove_file("/tmp/rsandbox-fsize-test");
    assert!(
        !output.success(),
        "expected SIGXFSZ, got {:?}",
        output.status
    );
}

#[test]
fn surfaces_a_missing_binary() {
    let spec = spec();
    let mut sandbox = create(&spec);
    let err = sandbox
        .exec(&ExecRequest::new(["/nonexistent/rsandbox-binary"]))
        .expect_err("a missing binary must fail");
    assert!(matches!(err, SandboxError::Io(_)), "got {err:?}");
}

#[test]
fn refuses_to_run_after_terminate() {
    let spec = spec();
    let mut sandbox = create(&spec);
    sandbox
        .terminate(Duration::ZERO)
        .expect("terminate succeeds");
    let err = sandbox
        .exec(&ExecRequest::new(["/bin/echo", "hi"]))
        .expect_err("a terminated sandbox must not run");
    assert!(matches!(err, SandboxError::Terminated(_)), "got {err:?}");
}

#[test]
fn refuses_specs_it_cannot_honour() {
    // Fail closed. The portable backend cannot isolate the network, so anything
    // but an explicit `Host` must be rejected at `create` — never downgraded to
    // "runs with host networking anyway".
    let mut no_network = spec();
    no_network.net = NetPolicy::Deny;
    let backend = rsandbox::registry().resolve(&no_network).expect("resolves");
    assert!(
        matches!(
            backend.create(&no_network),
            Err(SandboxError::Unsupported { .. })
        ),
        "a network policy the backend cannot enforce must be rejected"
    );

    // Likewise for a filesystem jail.
    let mut with_rootfs = spec();
    with_rootfs.fs.rootfs = Some("/some/rootfs".into());
    let backend = rsandbox::registry()
        .resolve(&with_rootfs)
        .expect("resolves");
    assert!(matches!(
        backend.create(&with_rootfs),
        Err(SandboxError::Unsupported { .. })
    ));
}

#[test]
fn refuses_an_empty_argv() {
    let spec = spec();
    let mut sandbox = create(&spec);
    let err = sandbox
        .exec(&ExecRequest::default())
        .expect_err("an empty argv must fail");
    assert!(matches!(err, SandboxError::InvalidSpec(_)), "got {err:?}");
}
