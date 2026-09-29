use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{ExecOutput, ExecRequest, Result, SandboxId, SandboxSpec};

/// The strongest isolation boundary a backend can establish.
///
/// Ordered from weakest to strongest so that [`crate::Registry`] can prefer the
/// strongest backend available on a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    /// No OS boundary: only cooperative restrictions (env scrubbing, cwd).
    None,
    /// A plain child process with rlimits and process-group lifetime control.
    Process,
    /// Kernel namespaces: pid / mount / net / ipc / uts.
    Namespaces,
    /// Namespaces plus an unprivileged user namespace with uid/gid mapping,
    /// which removes the need for a privileged supervisor.
    UserNamespaces,
    /// Hardware-virtualised microVM (KVM/Firecracker class).
    MicroVm,
    /// WebAssembly bytecode sandbox (wasmtime class).
    Wasm,
}

/// Machine-readable description of what a backend actually enforces. Callers
/// (schedulers, admission control) use this to reject a spec before any
/// workload starts, instead of discovering the gap at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub isolation: IsolationLevel,
    /// Can confine filesystem access (Landlock, pivot_root, WASI preopens).
    pub filesystem_jail: bool,
    /// Can filter system calls (seccomp-bpf, WASM validation).
    pub syscall_filter: bool,
    /// Can cut off or filter network egress.
    pub network_isolation: bool,
    /// Can enforce CPU / memory / pid budgets.
    pub resource_limits: bool,
    /// Can snapshot a warmed sandbox and fork it for sub-millisecond cold starts.
    pub snapshot_fork: bool,
    /// `std::env::consts::OS` values this backend supports.
    pub supported_os: Vec<String>,
}

/// Lifecycle state of a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    /// Created and validated, no workload has run yet.
    Ready,
    /// [`Sandbox::terminate`] has been called.
    Terminated,
}

/// A pluggable isolation primitive.
///
/// Implementations are registered once and shared across threads, so they must
/// be cheap to clone (use `Arc` for shared state) and must not hold per-sandbox
/// state — that belongs in the [`Sandbox`] they return.
pub trait Backend: Send + Sync + 'static {
    /// Stable name used to pin a backend in [`SandboxSpec::backend`].
    fn name(&self) -> &'static str;

    /// What this backend can enforce on the current host. Must reflect the
    /// *runtime* situation (kernel version, available features), not just the
    /// compile-time platform.
    fn capabilities(&self) -> Capabilities;

    /// Validate `spec` and instantiate a sandbox. Fails with
    /// [`crate::SandboxError::Unsupported`] when the spec asks for a guarantee
    /// this backend cannot provide.
    fn create(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>>;
}

/// A live sandbox bound to one backend.
///
/// `exec` is synchronous: it spawns the command, enforces the budget, drains its
/// output and returns once the process is reaped. A high-throughput daemon
/// wraps this in a blocking pool rather than reimplementing the isolation logic.
pub trait Sandbox: Send {
    fn id(&self) -> &SandboxId;

    fn state(&self) -> SandboxState;

    /// Run one command under the sandbox's policy.
    fn exec(&mut self, req: &ExecRequest) -> Result<ExecOutput>;

    /// Kill anything still running and release kernel resources (namespaces,
    /// cgroups, mounts). Idempotent.
    fn terminate(&mut self, grace: Duration) -> Result<()>;
}
