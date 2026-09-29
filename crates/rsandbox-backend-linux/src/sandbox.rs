use std::ffi::{CStr, CString, OsStr};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rsandbox_core::{
    Backend, Capabilities, ExecOutput, ExecRequest, IsolationLevel, NetPolicy, Result, Sandbox,
    SandboxError, SandboxId, SandboxSpec, SandboxState,
};
use rsandbox_unix::{capture, env, limits, supervise, wait};

use crate::cgroup::Cgroup;
use crate::landlock_fs;
use crate::probe::{self, KernelFeatures};
use crate::seccomp;

/// Name used to pin this backend in [`SandboxSpec::backend`].
pub const BACKEND_NAME: &str = "linux";

/// Sentinel errnos used to name a child-side setup failure. The forked child can
/// only relay an errno through `Command`'s status pipe, so the backend reserves
/// one value per step that has no errno of its own. These are diagnostics, not a
/// contract: a genuine syscall failure returning the same errno is merely
/// reported under the wrong step name.
const ERR_LANDLOCK: i32 = libc::EACCES;
const ERR_SECCOMP: i32 = libc::EPERM;

/// NUL-terminated paths the child writes, as byte literals so nothing is
/// allocated after the fork.
const PROC_SELF_SETGROUPS: &[u8] = b"/proc/self/setgroups\0";
const PROC_SELF_UID_MAP: &[u8] = b"/proc/self/uid_map\0";
const PROC_SELF_GID_MAP: &[u8] = b"/proc/self/gid_map\0";
const SETGROUPS_DENY: &[u8] = b"deny";

pub struct LinuxBackend {
    features: KernelFeatures,
}

impl LinuxBackend {
    pub fn new() -> Self {
        Self {
            features: probe::detect(),
        }
    }

    /// What the host supported when the backend was created.
    pub fn features(&self) -> KernelFeatures {
        self.features
    }
}

impl Default for LinuxBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for LinuxBackend {
    fn name(&self) -> &'static str {
        BACKEND_NAME
    }

    fn capabilities(&self) -> Capabilities {
        let features = self.features;
        Capabilities {
            // Without a user namespace an unprivileged supervisor cannot create
            // any of the other namespaces, so there is no isolation to promise.
            isolation: if features.user_namespaces {
                IsolationLevel::UserNamespaces
            } else {
                IsolationLevel::None
            },
            filesystem_jail: features.has_landlock(),
            syscall_filter: features.seccomp,
            network_isolation: features.user_namespaces,
            resource_limits: true,
            snapshot_fork: false,
            supported_os: vec!["linux".into()],
        }
    }

    fn create(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>> {
        LinuxSandbox::prepare(self.features, spec.clone()).map(|s| Box::new(s) as Box<dyn Sandbox>)
    }
}

/// Reject a spec this host cannot honour, before any workload starts.
fn validate(features: KernelFeatures, spec: &SandboxSpec) -> Result<()> {
    let reject = |what: String| -> Result<()> {
        Err(SandboxError::Unsupported {
            backend: BACKEND_NAME,
            what,
        })
    };

    if !features.user_namespaces {
        return reject(
            "any isolation (unprivileged user namespaces are disabled on this host)".into(),
        );
    }
    if spec.fs.rootfs.is_some() {
        return reject(
            "fs.rootfs (root filesystem images are not implemented yet; confine with fs.read_allow / fs.write_allow instead)"
                .into(),
        );
    }
    if !spec.fs.mounts.is_empty() {
        return reject("fs.mounts (not implemented yet)".into());
    }
    if !spec.fs.workdir.is_absolute() {
        return reject(format!(
            "relative fs.workdir `{}`",
            spec.fs.workdir.display()
        ));
    }
    let wants_fs_jail = !spec.fs.read_allow.is_empty() || !spec.fs.write_allow.is_empty();
    if wants_fs_jail && !features.has_landlock() {
        return reject(
            "fs.read_allow / fs.write_allow (this kernel has no Landlock support)".into(),
        );
    }
    match &spec.net {
        // An egress allowlist needs a filtering proxy or nftables rules. Neither
        // exists yet, and pretending to filter would be worse than refusing.
        NetPolicy::Allow(_) => reject(
            "net = Allow(..) (egress filtering is not implemented yet; use Deny, Loopback or Host)"
                .into(),
        ),
        _ => Ok(()),
    }
}

pub struct LinuxSandbox {
    id: SandboxId,
    spec: SandboxSpec,
    state: SandboxState,
    /// Compiled once: the filter is identical for every `exec`.
    seccomp: seccompiler::BpfProgram,
    /// Built once and inherited by every child.
    landlock: Option<std::os::fd::OwnedFd>,
    cgroup: Option<Cgroup>,
}

impl LinuxSandbox {
    fn prepare(features: KernelFeatures, spec: SandboxSpec) -> Result<Self> {
        validate(features, &spec)?;

        let seccomp = seccomp::default_filter().map_err(SandboxError::Setup)?;
        let landlock = match landlock_fs::abi(features.landlock_abi) {
            Some(abi) => Some(landlock_fs::build(&spec.fs, abi).map_err(SandboxError::Setup)?),
            None => None,
        };

        let id = SandboxId::generate();
        // A cgroup is what turns per-process rlimits into whole-tree budgets, so
        // its absence is a real downgrade. It only becomes fatal when the spec
        // asks for something rlimits cannot express.
        let cgroup = match Cgroup::create(id.as_str(), &spec.resources) {
            Ok(cgroup) => Some(cgroup),
            Err(err) if spec.resources.cpu_weight.is_some() => return Err(err),
            Err(_) => None,
        };

        Ok(Self {
            id,
            spec,
            state: SandboxState::Ready,
            seccomp,
            landlock,
            cgroup,
        })
    }
}

impl Sandbox for LinuxSandbox {
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

        let prepared = Arc::new(Prepared::new(self, req)?);

        let mut cmd = Command::new(&req.argv[0]);
        cmd.args(&req.argv[1..]);
        env::apply(&self.spec.env, &mut cmd, &req.env);
        // No `current_dir`: the child chdirs itself once the mount namespace
        // exists, so the path resolves inside the sandbox.
        supervise::configure_stdio(&mut cmd, !req.stdin.is_empty());

        let child_prepared = Arc::clone(&prepared);
        // SAFETY: `child_setup` runs in the forked child before `exec` and
        // performs only async-signal-safe syscalls — it never allocates, locks or
        // touches the Rust runtime. On failure it returns an errno, which
        // `Command` relays, so `spawn` fails instead of running a half-built
        // sandbox.
        unsafe {
            cmd.pre_exec(move || child_setup(&child_prepared));
        }

        let started = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|err| SandboxError::Setup(decode_setup_error(&err)))?;
        let pgid = child.id() as i32;

        let stdout = child.stdout.take().map(capture::spawn_reader);
        let stderr = child.stderr.take().map(capture::spawn_reader);
        let stdin = child
            .stdin
            .take()
            .map(|pipe| supervise::write_stdin(pipe, req.stdin.clone()));

        let timeout = supervise::deadline(req, &self.spec.resources);
        // Killing the cgroup reaches every process in the sandbox, including any
        // that changed its own process group; the group kill is the fallback for
        // when no cgroup could be created.
        let cgroup = self.cgroup.as_ref();
        let output = supervise::run(
            &mut child,
            timeout,
            started,
            &self.spec.resources,
            || {
                if let Some(cgroup) = cgroup {
                    let _ = cgroup.kill();
                }
                wait::kill_group(pgid);
            },
            stdout,
            stderr,
        )?;
        drop(stdin);
        Ok(output)
    }

    fn terminate(&mut self, _grace: Duration) -> Result<()> {
        if let Some(cgroup) = &self.cgroup {
            // Atomic and namespace-agnostic: catches processes that escaped the
            // original process group.
            let _ = cgroup.kill();
        }
        self.state = SandboxState::Terminated;
        Ok(())
    }
}

/// Everything the forked child needs, prepared in the supervisor so that the
/// child allocates nothing and only issues async-signal-safe syscalls.
struct Prepared {
    /// Namespaces to create *after* the user namespace, which always comes first
    /// and on its own so the uid/gid mappings can be written.
    ns_flags: libc::c_int,
    /// `"0 <host uid> 1\n"` mapping for the new user namespace.
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    /// tmpfs mount points, NUL-terminated for the raw `mount` call.
    tmpfs: Vec<CString>,
    /// Landlock ruleset to install. Borrowed rather than duplicated: the parent
    /// keeps the `OwnedFd` alive for the whole `exec`.
    landlock_fd: Option<libc::c_int>,
    /// Compiled seccomp program to install.
    seccomp: seccompiler::BpfProgram,
    /// `cgroup.procs` to join, so budgets cover the workload from its first
    /// instruction.
    cgroup_procs: Option<CString>,
    /// Where the workload should start.
    workdir: CString,
    limits: rsandbox_core::ResourceLimits,
}

impl Prepared {
    fn new(sandbox: &LinuxSandbox, req: &ExecRequest) -> Result<Self> {
        let spec = &sandbox.spec;

        let mut ns_flags = libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
        if !matches!(spec.net, NetPolicy::Host) {
            ns_flags |= libc::CLONE_NEWNET;
        }

        // SAFETY: `geteuid`/`getegid` have no preconditions and cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };

        let tmpfs = spec
            .fs
            .tmpfs
            .iter()
            .map(|path| cstring(path.as_os_str(), "fs.tmpfs"))
            .collect::<Result<Vec<_>>>()?;

        let workdir = req
            .workdir
            .clone()
            .unwrap_or_else(|| spec.fs.workdir.clone());

        let cgroup_procs = sandbox
            .cgroup
            .as_ref()
            .map(|cgroup| cstring(cgroup.procs_path().as_os_str(), "cgroup.procs"))
            .transpose()?;

        Ok(Self {
            ns_flags,
            uid_map: format!("0 {uid} 1\n").into_bytes(),
            gid_map: format!("0 {gid} 1\n").into_bytes(),
            tmpfs,
            landlock_fd: sandbox.landlock.as_ref().map(AsRawFd::as_raw_fd),
            seccomp: sandbox.seccomp.clone(),
            cgroup_procs,
            workdir: cstring(workdir.as_os_str(), "fs.workdir")?,
            limits: spec.resources.clone(),
        })
    }
}

/// Runs in the forked child, before `exec`.
///
/// Only async-signal-safe operations are permitted here: no allocation, no
/// locking, no Rust runtime services. Every fallible step returns an error, which
/// `Command` relays to the supervisor, so a partially configured sandbox never
/// silently becomes a running workload.
fn child_setup(prepared: &Prepared) -> std::io::Result<()> {
    // SAFETY: every call below is a raw syscall on values prepared before the
    // fork; nothing here allocates or touches shared runtime state.
    unsafe {
        // 1. The user namespace comes first and alone: it is what lets an
        //    unprivileged process create the remaining namespaces, and the
        //    mappings must exist before anything needs the capabilities it grants.
        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        write_path(PROC_SELF_SETGROUPS, SETGROUPS_DENY)?;
        write_path(PROC_SELF_UID_MAP, &prepared.uid_map)?;
        write_path(PROC_SELF_GID_MAP, &prepared.gid_map)?;

        // 2. The remaining namespaces. Network is skipped when the policy asks
        //    for host networking.
        if libc::unshare(prepared.ns_flags) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // 3. Detach our mount namespace so the tmpfs mounts below cannot
        //    propagate back into the host namespace.
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        for target in &prepared.tmpfs {
            // Best effort: the mount point normally already exists (`/tmp`).
            libc::mkdir(target.as_ptr(), 0o1777);
            if libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=1777".as_ptr().cast(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }

        // 4. Own process group, so a deadline kill reaches every process the
        //    workload spawns.
        if libc::setsid() == -1 {
            return Err(std::io::Error::last_os_error());
        }

        // 5. Filesystem confinement. Landlock requires `no_new_privs`, which
        //    seccomp would set anyway; doing it here keeps the ordering explicit.
        if let Some(fd) = prepared.landlock_fd {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_landlock_restrict_self,
                libc::c_long::from(fd),
                0 as libc::c_long,
            ) != 0
            {
                return Err(std::io::Error::from_raw_os_error(ERR_LANDLOCK));
            }
            // The ruleset is live; drop the descriptor so it cannot leak into the
            // workload. This closes the child's copy only.
            libc::close(fd);
        }

        // 6. Join the sandbox's cgroup before exec, so the budget covers the
        //    workload from its very first instruction.
        if let Some(procs) = &prepared.cgroup_procs {
            join_cgroup(procs)?;
        }

        // 7. Per-process budgets, inherited by everything the workload spawns.
        limits::apply_limits(&prepared.limits)?;

        // 8. The syscall filter goes on last, immediately before exec: nothing
        //    after this point may need a syscall the filter denies.
        seccomp::install(&prepared.seccomp)?;

        // 9. Start where the policy asked. Done here rather than through
        //    `Command::current_dir` so the path resolves inside the mount
        //    namespace just built.
        if libc::chdir(prepared.workdir.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Convert a path into a `CString`, reporting a NUL byte as a spec error rather
/// than panicking.
fn cstring(path: &OsStr, field: &str) -> Result<CString> {
    CString::new(path.as_bytes()).map_err(|_| {
        SandboxError::InvalidSpec(format!(
            "{field} contains a NUL byte: {}",
            path.to_string_lossy()
        ))
    })
}

/// Write `data` to the NUL-terminated `path` using raw syscalls.
///
/// # Safety
/// `path` must be NUL-terminated.
unsafe fn write_path(path: &[u8], data: &[u8]) -> std::io::Result<()> {
    // SAFETY: `path` is NUL-terminated per the contract above.
    let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = write_all(fd, data);
    // SAFETY: `fd` was opened above and has not been closed.
    unsafe { libc::close(fd) };
    result
}

/// `write(2)` the whole buffer, retrying on short writes and `EINTR`.
fn write_all(fd: libc::c_int, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        // SAFETY: `fd` is an open descriptor and `data` is a valid slice.
        let written = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        data = &data[written as usize..];
    }
    Ok(())
}

/// Add the calling process to the cgroup whose `cgroup.procs` is `procs`,
/// rendering its own pid without allocating.
fn join_cgroup(procs: &CStr) -> std::io::Result<()> {
    let mut digits = [0u8; 12];
    // SAFETY: `getpid` has no preconditions.
    let text = render_u32(unsafe { libc::getpid() } as u32, &mut digits);
    let mut payload = [0u8; 13];
    payload[..text.len()].copy_from_slice(text);
    payload[text.len()] = b'\n';
    let len = text.len() + 1;
    // SAFETY: `procs` is a valid C string and `payload[..len]` is a valid buffer.
    unsafe { write_path(procs.to_bytes_with_nul(), &payload[..len]) }
}

/// Render `value` as decimal into `buf`, returning the used prefix.
fn render_u32(mut value: u32, buf: &mut [u8; 12]) -> &[u8] {
    let mut len = 0;
    loop {
        buf[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
        if value == 0 {
            break;
        }
    }
    buf[..len].reverse();
    &buf[..len]
}

/// Name the child-side step that failed.
fn decode_setup_error(err: &std::io::Error) -> String {
    match err.raw_os_error() {
        Some(ERR_LANDLOCK) => {
            format!("sandbox setup failed installing the Landlock ruleset: {err}")
        }
        Some(ERR_SECCOMP) => format!("sandbox setup failed installing the seccomp filter: {err}"),
        _ => format!("sandbox setup failed in the sandboxed child: {err}"),
    }
}
