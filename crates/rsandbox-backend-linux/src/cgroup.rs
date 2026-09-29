//! cgroup v2 resource enforcement.
//!
//! A per-sandbox cgroup turns per-process `RLIMIT_*` budgets into whole-tree
//! accounting, and gives `terminate` an atomic way to kill every process in the
//! sandbox — including ones that changed their own process group to escape a
//! `killpg`.
//!
//! cgroup v2 forbids a cgroup from having both member processes and enabled
//! controllers, so sandbox cgroups are created *inside* a delegated parent. That
//! parent comes from `RSANDBOX_CGROUP_ROOT` when the deployment provides one —
//! the recommended setup, e.g. a systemd unit with `Delegate=yes`, or a container
//! given a delegated subtree. Without it we fall back to `rsandbox` under the
//! unified root, which only works when the supervisor may create it.

use std::fs;
use std::path::{Path, PathBuf};

use rsandbox_core::{ResourceLimits, Result, SandboxError};

/// Environment variable pointing at a writable, delegated cgroup v2 subtree.
pub const CGROUP_ROOT_ENV: &str = "RSANDBOX_CGROUP_ROOT";

const UNIFIED_ROOT: &str = "/sys/fs/cgroup";
const SUBDIR: &str = "rsandbox";

pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Create the sandbox's cgroup and apply `limits` before any workload runs.
    pub fn create(id: &str, limits: &ResourceLimits) -> Result<Self> {
        let parent = parent_dir()?;
        fs::create_dir_all(&parent)
            .map_err(|err| setup(format!("create {}: {err}", parent.display())))?;
        enable_controllers(&parent);

        let path = parent.join(id);
        fs::create_dir(&path)
            .map_err(|err| setup(format!("create cgroup {}: {err}", path.display())))?;

        let cgroup = Self { path };
        cgroup.apply(limits)?;
        Ok(cgroup)
    }

    /// `cgroup.procs`, which the sandboxed child writes its own pid to
    /// immediately before `exec` so no workload work happens outside the budget.
    pub fn procs_path(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }

    fn apply(&self, limits: &ResourceLimits) -> Result<()> {
        if let Some(bytes) = limits.memory_bytes {
            self.write("memory.max", &bytes.to_string())?;
            // Without this a workload can dodge the memory budget by swapping.
            self.write("memory.swap.max", "0")?;
        }
        if let Some(max) = limits.pids_max {
            self.write("pids.max", &max.to_string())?;
        }
        if let Some(weight) = limits.cpu_weight {
            // `cpu.weight` is the relative share (1..=10000). A total CPU *time*
            // budget has no cgroup v2 equivalent and is enforced by RLIMIT_CPU.
            self.write("cpu.weight", &weight.to_string())?;
        }
        Ok(())
    }

    fn write(&self, file: &str, value: &str) -> Result<()> {
        let path = self.path.join(file);
        // A kernel without the controller reports an error here. That is a real
        // inability to enforce the budget, so it must surface rather than pass.
        fs::write(&path, value)
            .map_err(|err| setup(format!("write {} = {value}: {err}", path.display())))
    }

    /// Kill every process in the sandbox.
    ///
    /// `cgroup.kill` (Linux 5.14+) is atomic and namespace-agnostic; older
    /// kernels fall back to signalling each member.
    pub fn kill(&self) -> Result<()> {
        if fs::write(self.path.join("cgroup.kill"), "1").is_ok() {
            return Ok(());
        }
        let procs = fs::read_to_string(self.path.join("cgroup.procs")).unwrap_or_default();
        for line in procs.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                // SAFETY: plain signal delivery to a pid we just read from the
                // kernel; a stale pid can only cost a lost signal.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        Ok(())
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // The directory disappears once its last process has been reaped, so
        // removal is best effort on every path.
        let _ = self.kill();
        let _ = fs::remove_dir(&self.path);
    }
}

fn parent_dir() -> Result<PathBuf> {
    match std::env::var_os(CGROUP_ROOT_ENV) {
        Some(root) => {
            let root = PathBuf::from(root);
            if root.is_absolute() {
                Ok(root)
            } else {
                Err(setup(format!(
                    "{CGROUP_ROOT_ENV} must be an absolute path, got {}",
                    root.display()
                )))
            }
        }
        None => Ok(Path::new(UNIFIED_ROOT).join(SUBDIR)),
    }
}

/// Best effort: ask the kernel to expose the controllers we need to children of
/// the delegated root. A deployment that pre-enabled them (systemd `Delegate=`)
/// makes this a no-op, and a failure here resurfaces as a hard error from the
/// first `write` that needs a controller.
fn enable_controllers(parent: &Path) {
    let _ = fs::write(parent.join("cgroup.subtree_control"), "+cpu +memory +pids");
}

fn setup(message: String) -> SandboxError {
    SandboxError::Setup(format!("cgroup: {message}"))
}
