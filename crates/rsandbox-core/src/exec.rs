use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A single command to run inside an existing sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecRequest {
    /// `argv`, executed without a shell. Callers that need shell semantics must
    /// pass an explicit `["/bin/sh", "-c", …]`.
    pub argv: Vec<String>,
    /// Per-call environment additions layered on top of the sandbox's policy.
    pub env: BTreeMap<String, String>,
    /// Override the sandbox working directory for this call.
    pub workdir: Option<PathBuf>,
    /// Override `ResourceLimits::wall_time_ms` for this call.
    pub timeout: Option<Duration>,
    /// Bytes written to the child's stdin before it is closed.
    pub stdin: Vec<u8>,
}

impl ExecRequest {
    /// Build a request from an argv-style iterator.
    pub fn new<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }
}

/// How a sandboxed process finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    /// Terminated normally with this exit code.
    Exited(i32),
    /// Killed by a signal.
    Signaled(i32),
    /// Killed because it exceeded the wall-clock deadline.
    TimedOut,
    /// Killed by the kernel or the supervisor for exceeding a budget
    /// (memory, CPU time, pids, …).
    Killed,
}

impl ExitStatus {
    pub fn success(self) -> bool {
        matches!(self, ExitStatus::Exited(0))
    }

    /// Process exit code, following shell conventions (128 + signal).
    pub fn code(self) -> i32 {
        match self {
            ExitStatus::Exited(code) => code,
            ExitStatus::Signaled(sig) => 128 + sig,
            ExitStatus::TimedOut => 124,
            ExitStatus::Killed => 137,
        }
    }
}

/// Result of a single [`ExecRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
    /// True when stdout or stderr hit the capture cap and was cut short.
    pub truncated: bool,
}

impl ExecOutput {
    pub fn success(&self) -> bool {
        self.status.success()
    }
}
