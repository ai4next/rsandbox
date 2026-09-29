use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Stable identifier for a sandbox instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SandboxId(String);

impl SandboxId {
    /// Mint an id that is unique within the current process.
    pub fn generate() -> Self {
        Self(format!(
            "sbx-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl std::fmt::Display for SandboxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resource budget enforced for the sandbox. Every field is optional; `None`
/// means "inherit the host default", which is intentionally the *only* place
/// where host policy leaks in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceLimits {
    /// Hard wall-clock deadline for a single [`crate::ExecRequest`], in ms.
    pub wall_time_ms: Option<u64>,
    /// CPU time budget (RLIMIT_CPU / cgroup `cpu.max`), in ms.
    pub cpu_time_ms: Option<u64>,
    /// Address-space cap (RLIMIT_AS / cgroup `memory.max`), in bytes.
    pub memory_bytes: Option<u64>,
    /// Max live processes and threads (RLIMIT_NPROC / cgroup `pids.max`).
    pub pids_max: Option<u32>,
    /// Max open file descriptors (RLIMIT_NOFILE).
    pub open_files_max: Option<u64>,
    /// Max size of a single file the workload may create (RLIMIT_FSIZE), bytes.
    pub file_size_bytes: Option<u64>,
    /// CPU scheduling weight for cgroup v2 `cpu.weight` (1..=10000).
    pub cpu_weight: Option<u32>,
}

/// How a [`Mount`] is materialised inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountKind {
    /// Bind-mount `source` (a host path) onto `target`.
    Bind,
    /// Fresh anonymous memory filesystem at `target`.
    Tmpfs,
    /// Kernel `procfs` at `target`.
    Proc,
    /// Minimal `/dev` (null, zero, random, urandom).
    Dev,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    /// Host path for [`MountKind::Bind`]; ignored for the synthetic kinds.
    pub source: Option<PathBuf>,
    /// Absolute path inside the sandbox.
    pub target: PathBuf,
    pub kind: MountKind,
    #[serde(default)]
    pub read_only: bool,
}

/// What the workload can see of the filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FsPolicy {
    /// Root filesystem to pivot into. `None` means "inherit the host root,
    /// read-only", which is only meaningful for the portable backends.
    pub rootfs: Option<PathBuf>,
    pub mounts: Vec<Mount>,
    /// Working directory inside the sandbox.
    pub workdir: PathBuf,
    /// Paths backed by an anonymous tmpfs, i.e. the writable scratch space.
    pub tmpfs: Vec<PathBuf>,
    /// Extra host paths the workload may read, expressed as Landlock rules on
    /// Linux. Ignored by backends without a filesystem jail.
    pub read_allow: Vec<PathBuf>,
    /// Extra host paths the workload may write.
    pub write_allow: Vec<PathBuf>,
}

impl Default for FsPolicy {
    fn default() -> Self {
        Self {
            rootfs: None,
            mounts: Vec::new(),
            workdir: PathBuf::from("/"),
            tmpfs: vec![PathBuf::from("/tmp")],
            read_allow: Vec::new(),
            write_allow: Vec::new(),
        }
    }
}

/// Egress policy for the sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetPolicy {
    /// Fresh network namespace with loopback down: no connectivity at all.
    #[default]
    Deny,
    /// Loopback only.
    Loopback,
    /// Egress restricted to the listed endpoints (`host`, `host:port` or CIDR).
    /// Enforcement is backend-specific; a backend that cannot enforce it must
    /// reject the spec instead of silently allowing the traffic.
    Allow(Vec<String>),
    /// Share the host network namespace. Trusted workloads only.
    Host,
}

/// Environment the workload starts with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvPolicy {
    /// Start from an empty environment rather than inheriting the host's.
    pub clear: bool,
    pub vars: BTreeMap<String, String>,
}

impl Default for EnvPolicy {
    fn default() -> Self {
        // Secure by default: a sandbox must not leak the host environment
        // (tokens, proxies, credentials) unless it is asked to.
        Self {
            clear: true,
            vars: BTreeMap::new(),
        }
    }
}

/// The declarative description of a sandbox. Backends translate this into
/// kernel primitives; nothing here is backend-specific.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxSpec {
    /// Human-readable label, e.g. the agent session it belongs to.
    pub name: Option<String>,
    pub resources: ResourceLimits,
    pub fs: FsPolicy,
    pub net: NetPolicy,
    pub env: EnvPolicy,
    /// Pin a backend by name. `None` lets the registry pick the strongest one.
    pub backend: Option<String>,
    /// Free-form metadata for scheduling and audit trails.
    pub labels: BTreeMap<String, String>,
}
