use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use rsandbox_core::{
    Backend, Capabilities, ExecOutput, ExecRequest, IsolationLevel, NetPolicy, Result, Sandbox,
    SandboxError, SandboxId, SandboxSpec, SandboxState,
};
use rsandbox_unix::{capture, env, limits, supervise, wait};

/// Name used to pin this backend in [`SandboxSpec::backend`].
pub const BACKEND_NAME: &str = "process";

/// The portable backend. Stateless, so a single instance is shared.
#[derive(Debug, Default)]
pub struct ProcessBackend;

impl ProcessBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for ProcessBackend {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            isolation: IsolationLevel::Process,
            filesystem_jail: false,
            syscall_filter: false,
            network_isolation: false,
            resource_limits: true,
            snapshot_fork: false,
            supported_os: vec!["linux".into(), "macos".into()],
        }
    }

    fn create(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>> {
        validate(spec)?;
        Ok(Box::new(ProcessSandbox::new(spec.clone())))
    }
}

/// Reject any spec that asks for a guarantee this backend cannot provide.
/// Failing here — before a workload ever starts — is the whole point: a sandbox
/// must never run with less isolation than its caller believes it has.
fn validate(spec: &SandboxSpec) -> Result<()> {
    let reject = |what: String| -> Result<()> {
        Err(SandboxError::Unsupported {
            backend: BACKEND_NAME,
            what,
        })
    };

    if spec.fs.rootfs.is_some() {
        return reject("fs.rootfs (no filesystem jail; use the linux backend)".into());
    }
    if !spec.fs.mounts.is_empty() {
        return reject("fs.mounts (no filesystem jail; use the linux backend)".into());
    }
    if !spec.fs.read_allow.is_empty() || !spec.fs.write_allow.is_empty() {
        return reject("fs.read_allow / fs.write_allow (no filesystem jail)".into());
    }
    if !spec.fs.workdir.is_absolute() {
        return reject(format!(
            "relative fs.workdir `{}`",
            spec.fs.workdir.display()
        ));
    }
    match spec.net {
        NetPolicy::Host => Ok(()),
        ref other => reject(format!(
            "net = {other:?} (this backend cannot isolate the network; opt in explicitly with NetPolicy::Host)"
        )),
    }
}

pub struct ProcessSandbox {
    id: SandboxId,
    spec: SandboxSpec,
    state: SandboxState,
}

impl ProcessSandbox {
    fn new(spec: SandboxSpec) -> Self {
        Self {
            id: SandboxId::generate(),
            spec,
            state: SandboxState::Ready,
        }
    }
}

impl Sandbox for ProcessSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn state(&self) -> SandboxState {
        self.state
    }

    fn exec(&mut self, req: &ExecRequest) -> Result<ExecOutput> {
        if self.state == SandboxState::Terminated {
            return Err(SandboxError::Terminated(self.id.clone()));
        }
        if req.argv.is_empty() {
            return Err(SandboxError::InvalidSpec("argv must not be empty".into()));
        }

        let mut cmd = Command::new(&req.argv[0]);
        cmd.args(&req.argv[1..]);
        env::apply(&self.spec.env, &mut cmd, &req.env);
        cmd.current_dir(
            req.workdir
                .clone()
                .unwrap_or_else(|| self.spec.fs.workdir.clone()),
        );
        supervise::configure_stdio(&mut cmd, !req.stdin.is_empty());

        // Budgets are applied in the forked child, immediately before `exec`, so
        // the workload cannot raise them and the supervisor is never affected.
        // `setsid` gives the workload its own process group, which is what lets a
        // deadline kill reach every process it spawns.
        let limits = self.spec.resources.clone();
        // SAFETY: the closure runs in the forked child before `exec` and only
        // performs async-signal-safe `libc` calls (setsid/setrlimit). On failure
        // it returns an error, which `Command` relays through its status pipe and
        // turns into a `spawn()` error rather than a half-configured sandbox.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                limits::apply_limits(&limits)
            });
        }

        let started = Instant::now();
        let mut child = cmd.spawn()?;
        let pgid = child.id() as i32;

        let stdout = child.stdout.take().map(capture::spawn_reader);
        let stderr = child.stderr.take().map(capture::spawn_reader);
        let stdin = child
            .stdin
            .take()
            .map(|pipe| supervise::write_stdin(pipe, req.stdin.clone()));

        let timeout = supervise::deadline(req, &self.spec.resources);
        let output = supervise::run(
            &mut child,
            timeout,
            started,
            &self.spec.resources,
            || wait::kill_group(pgid),
            stdout,
            stderr,
        )?;
        drop(stdin);
        Ok(output)
    }

    fn terminate(&mut self, _grace: Duration) -> Result<()> {
        // `exec` is synchronous and holds `&mut self`, so no workload can be
        // alive here. Marking the sandbox terminated is enough for this backend;
        // a backend holding persistent kernel resources (cgroups, mounts) must
        // also tear those down.
        self.state = SandboxState::Terminated;
        Ok(())
    }
}
