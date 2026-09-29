//! Behaviour of the backend-agnostic API: defaults, serialization, and the
//! registry contract that admission control depends on.

use rsandbox::{ExitStatus, NetPolicy, SandboxSpec};

#[test]
fn defaults_are_secure() {
    let spec = SandboxSpec::default();
    // A sandbox must not inherit the host environment or the host network by
    // accident; both have to be opted into.
    assert!(spec.env.clear, "the environment must be cleared by default");
    assert!(spec.env.vars.is_empty());
    assert_eq!(spec.net, NetPolicy::Deny);
}

#[test]
fn missing_json_fields_fall_back_to_defaults() {
    let spec: SandboxSpec = serde_json::from_str("{}").expect("an empty object is a valid spec");
    assert_eq!(spec, SandboxSpec::default());
    assert!(
        spec.env.clear,
        "serde defaults must preserve the secure default"
    );
}

#[test]
fn spec_round_trips_through_json() {
    let mut spec = SandboxSpec {
        name: Some("agent-42".into()),
        net: NetPolicy::Loopback,
        ..SandboxSpec::default()
    };
    spec.env.vars.insert("PYTHONPATH".into(), "/opt/app".into());
    spec.resources.memory_bytes = Some(512 * 1024 * 1024);
    spec.fs.write_allow.push("/tmp/agent-42".into());

    let json = serde_json::to_string(&spec).expect("a spec serializes");
    let restored: SandboxSpec = serde_json::from_str(&json).expect("a spec deserializes");
    assert_eq!(spec, restored);
}

#[test]
fn unknown_fields_are_rejected() {
    // `deny_unknown_fields` is deliberate: a typo in a policy file must fail
    // loudly instead of silently weakening the sandbox.
    let result = serde_json::from_str::<SandboxSpec>(r#"{"netwrok":"deny"}"#);
    assert!(result.is_err(), "a misspelled field must not be ignored");
}

#[test]
fn exit_status_follows_shell_conventions() {
    assert_eq!(ExitStatus::Exited(3).code(), 3);
    assert_eq!(ExitStatus::Signaled(9).code(), 137);
    assert_eq!(ExitStatus::TimedOut.code(), 124);
    assert_eq!(ExitStatus::Killed.code(), 137);
    assert!(ExitStatus::Exited(0).success());
    assert!(!ExitStatus::Killed.success());
}

#[test]
fn registry_reports_only_what_the_host_can_run() {
    let registry = rsandbox::registry();
    assert!(
        registry.get("process").is_some(),
        "the portable backend is available everywhere"
    );
    if !cfg!(target_os = "linux") {
        assert!(
            registry.get("linux").is_none(),
            "the Linux backend must not claim to work off Linux"
        );
    }

    let best = registry.best().expect("at least one backend is available");
    assert!(
        !best.capabilities().supported_os.is_empty(),
        "capabilities must name the platforms a backend supports"
    );
}
