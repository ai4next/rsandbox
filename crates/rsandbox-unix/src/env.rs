//! Environment translation shared by the backends.

use std::collections::BTreeMap;
use std::process::Command;

use rsandbox_core::EnvPolicy;

/// `PATH` injected when the policy clears the environment and supplies none, so
/// bare command names still resolve instead of depending on a libc-specific
/// fallback.
pub const FALLBACK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Translate a sandbox's [`EnvPolicy`] into the child's environment.
pub fn apply(policy: &EnvPolicy, cmd: &mut Command, overrides: &BTreeMap<String, String>) {
    if policy.clear {
        cmd.env_clear();
    }
    for (key, value) in &policy.vars {
        cmd.env(key, value);
    }
    for (key, value) in overrides {
        cmd.env(key, value);
    }
    let has_path = |vars: &BTreeMap<String, String>| vars.contains_key("PATH");
    if policy.clear && !has_path(&policy.vars) && !has_path(overrides) {
        cmd.env("PATH", FALLBACK_PATH);
    }
}
