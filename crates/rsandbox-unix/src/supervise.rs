//! Completion handling: deadline enforcement plus bounded output capture.

use std::io::{self, Write};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rsandbox_core::{ExecOutput, ExecRequest, ExitStatus, ResourceLimits};

use crate::capture::{self, Captured};
use crate::wait::{self, Wait};

/// The deadline for one `exec`: a per-call override wins over the sandbox's.
pub fn deadline(req: &ExecRequest, limits: &ResourceLimits) -> Option<Duration> {
    req.timeout
        .or_else(|| limits.wall_time_ms.map(Duration::from_millis))
}

/// Configure a child's standard streams for capture.
pub fn configure_stdio(cmd: &mut Command, has_stdin: bool) {
    cmd.stdin(if has_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
}

/// Feed `payload` to a child's stdin on a background thread.
///
/// A child that never reads its stdin closes the pipe early; that is its
/// prerogative, so a broken pipe is not an error.
pub fn write_stdin(pipe: impl Write + Send + 'static, payload: Vec<u8>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut pipe = pipe;
        let _ = pipe.write_all(&payload);
    })
}

/// Drive a spawned child to completion under `timeout`, then gather its output.
///
/// Every backend funnels through here so that deadline handling, tree killing and
/// output bounding behave identically no matter which isolation primitive is in
/// use. `on_timeout` performs the backend-specific kill.
pub fn run(
    child: &mut Child,
    timeout: Option<Duration>,
    started: Instant,
    limits: &ResourceLimits,
    on_timeout: impl FnMut(),
    stdout: Option<JoinHandle<Captured>>,
    stderr: Option<JoinHandle<Captured>>,
) -> io::Result<ExecOutput> {
    let status = match wait::wait_with_deadline(child, timeout, started, on_timeout)? {
        Wait::Exited(status) => wait::classify(status, limits),
        Wait::TimedOut => ExitStatus::TimedOut,
    };
    let (stdout, stderr, truncated) = capture::collect(stdout, stderr);
    Ok(ExecOutput {
        status,
        stdout,
        stderr,
        duration_ms: started.elapsed().as_millis() as u64,
        truncated,
    })
}
