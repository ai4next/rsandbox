use crate::SandboxId;

/// Convenience alias for results produced by this crate.
pub type Result<T, E = SandboxError> = std::result::Result<T, E>;

/// Everything that can go wrong while creating or driving a sandbox.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The requested backend name is not registered.
    #[error("unknown backend `{0}`")]
    BackendNotFound(String),

    /// The backend exists but cannot honour part of the spec. Callers must treat
    /// this as fatal rather than falling back to weaker isolation.
    #[error("backend `{backend}` cannot satisfy `{what}`")]
    Unsupported { backend: &'static str, what: String },

    #[error("sandbox `{0}` not found")]
    SandboxNotFound(SandboxId),

    #[error("invalid sandbox spec: {0}")]
    InvalidSpec(String),

    /// A kernel-side setup step (namespace, cgroup, seccomp, …) failed. The
    /// workload is never started in this case.
    #[error("sandbox setup failed: {0}")]
    Setup(String),

    #[error("sandbox `{0}` has already been terminated")]
    Terminated(SandboxId),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
