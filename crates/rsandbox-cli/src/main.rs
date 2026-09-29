use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use rsandbox::{ExecRequest, NetPolicy, SandboxSpec};

/// Run commands inside a secure, lightweight sandbox.
#[derive(Parser)]
#[command(name = "rsandbox", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the isolation backends available on this host.
    Backends {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Run a command inside a sandbox.
    Run(Box<RunArgs>),
}

#[derive(Args)]
struct RunArgs {
    /// Pin a backend by name (see `rsandbox backends`).
    #[arg(long)]
    backend: Option<String>,

    /// Load a full `SandboxSpec` from JSON; other flags then override it.
    #[arg(long, value_name = "FILE")]
    spec: Option<PathBuf>,

    /// Wall-clock deadline in milliseconds.
    #[arg(long)]
    timeout_ms: Option<u64>,

    /// Address-space cap in bytes.
    #[arg(long)]
    memory_bytes: Option<u64>,

    /// CPU-time budget in milliseconds.
    #[arg(long)]
    cpu_ms: Option<u64>,

    /// Max live processes and threads.
    #[arg(long)]
    pids: Option<u32>,

    /// Max open file descriptors.
    #[arg(long)]
    open_files: Option<u64>,

    /// Working directory inside the sandbox.
    #[arg(long)]
    workdir: Option<PathBuf>,

    /// Extra environment variable, repeatable (`--env K=V`).
    #[arg(long = "env", value_name = "K=V")]
    env: Vec<String>,

    /// Network policy: `host`, `deny` or `loopback`.
    #[arg(long, value_name = "POLICY")]
    net: Option<String>,

    /// Feed this file to the workload's stdin.
    #[arg(long, value_name = "FILE")]
    stdin: Option<PathBuf>,

    /// Emit a machine-readable result on stdout.
    #[arg(long)]
    json: bool,

    /// The command to run, following `--`.
    #[arg(trailing_var_arg = true, required = true, value_name = "CMD")]
    argv: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Backends { json } => list_backends(json),
        Command::Run(args) => run(*args),
    }
}

fn list_backends(json: bool) -> ExitCode {
    let registry = rsandbox::registry();
    let entries: Vec<_> = registry
        .list()
        .into_iter()
        .map(|(backend, caps)| {
            serde_json::json!({
                "name": backend.name(),
                "isolation": caps.isolation,
                "filesystem_jail": caps.filesystem_jail,
                "syscall_filter": caps.syscall_filter,
                "network_isolation": caps.network_isolation,
                "resource_limits": caps.resource_limits,
                "snapshot_fork": caps.snapshot_fork,
                "supported_os": caps.supported_os,
            })
        })
        .collect();

    if json {
        match serde_json::to_string_pretty(&entries) {
            Ok(text) => println!("{text}"),
            Err(err) => {
                eprintln!("rsandbox: {err}");
                return ExitCode::from(2);
            }
        }
        return ExitCode::SUCCESS;
    }

    for (backend, caps) in registry.list() {
        println!(
            "{:<9} isolation={:<15} fs_jail={:<5} seccomp={:<5} net_iso={:<5} rlimits={:<5} snapshot={:<5} os={}",
            backend.name(),
            format!("{:?}", caps.isolation).to_lowercase(),
            caps.filesystem_jail,
            caps.syscall_filter,
            caps.network_isolation,
            caps.resource_limits,
            caps.snapshot_fork,
            caps.supported_os.join(","),
        );
    }
    ExitCode::SUCCESS
}

fn run(args: RunArgs) -> ExitCode {
    let spec = match build_spec(&args) {
        Ok(spec) => spec,
        Err(err) => {
            eprintln!("rsandbox: {err}");
            return ExitCode::from(2);
        }
    };

    let registry = rsandbox::registry();
    let backend = match registry.resolve(&spec) {
        Ok(backend) => backend,
        Err(err) => {
            eprintln!("rsandbox: {err}");
            return ExitCode::from(2);
        }
    };

    let mut sandbox = match backend.create(&spec) {
        Ok(sandbox) => sandbox,
        Err(err) => {
            eprintln!("rsandbox: backend `{}`: {err}", backend.name());
            if !backend.capabilities().network_isolation && spec.net != NetPolicy::Host {
                // The default policy is `deny`, which is the right default, but
                // the portable backend cannot enforce it. Say so up front rather
                // than letting the user guess.
                eprintln!(
                    "hint: backend `{}` cannot isolate the network, so `--net host` is the only \
                     policy it accepts. Run `rsandbox backends` to see what each backend enforces.",
                    backend.name()
                );
            }
            return ExitCode::from(2);
        }
    };

    let mut request = ExecRequest::new(args.argv.clone());
    if let Some(path) = &args.stdin {
        match std::fs::read(path) {
            Ok(bytes) => request.stdin = bytes,
            Err(err) => {
                eprintln!("rsandbox: cannot read --stdin {}: {err}", path.display());
                return ExitCode::from(2);
            }
        }
    }

    let output = match sandbox.exec(&request) {
        Ok(output) => output,
        Err(err) => {
            eprintln!("rsandbox: {err}");
            let _ = sandbox.terminate(Duration::ZERO);
            return ExitCode::from(2);
        }
    };
    let _ = sandbox.terminate(Duration::ZERO);

    if args.json {
        let payload = serde_json::json!({
            "id": sandbox.id().as_str(),
            "backend": backend.name(),
            "isolation": backend.capabilities().isolation,
            "status": output.status,
            "exit_code": output.status.code(),
            "duration_ms": output.duration_ms,
            "truncated": output.truncated,
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
        });
        println!("{payload}");
    } else {
        let _ = std::io::stdout().write_all(&output.stdout);
        let _ = std::io::stderr().write_all(&output.stderr);
        eprintln!(
            "rsandbox: backend={} isolation={:?} status={:?} duration={}ms{}",
            backend.name(),
            backend.capabilities().isolation,
            output.status,
            output.duration_ms,
            if output.truncated {
                " truncated=true"
            } else {
                ""
            },
        );
    }

    ExitCode::from(u8::try_from(output.status.code().clamp(0, 255)).unwrap_or(1))
}

fn build_spec(args: &RunArgs) -> Result<SandboxSpec, String> {
    let mut spec = match &args.spec {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|err| format!("cannot read --spec {}: {err}", path.display()))?;
            serde_json::from_str(&text)
                .map_err(|err| format!("invalid --spec {}: {err}", path.display()))?
        }
        None => SandboxSpec::default(),
    };

    // Flags always win over the spec file, so a saved spec can be tweaked
    // per-invocation without rewriting it.
    if let Some(name) = &args.backend {
        spec.backend = Some(name.clone());
    }
    if let Some(value) = args.timeout_ms {
        spec.resources.wall_time_ms = Some(value);
    }
    if let Some(value) = args.memory_bytes {
        spec.resources.memory_bytes = Some(value);
    }
    if let Some(value) = args.cpu_ms {
        spec.resources.cpu_time_ms = Some(value);
    }
    if let Some(value) = args.pids {
        spec.resources.pids_max = Some(value);
    }
    if let Some(value) = args.open_files {
        spec.resources.open_files_max = Some(value);
    }
    if let Some(dir) = &args.workdir {
        spec.fs.workdir = dir.clone();
    }
    if let Some(policy) = &args.net {
        spec.net = parse_net(policy)?;
    }
    for entry in &args.env {
        let (key, value) = parse_env(entry)?;
        spec.env.vars.insert(key, value);
    }
    Ok(spec)
}

fn parse_net(value: &str) -> Result<NetPolicy, String> {
    match value {
        "host" => Ok(NetPolicy::Host),
        "deny" => Ok(NetPolicy::Deny),
        "loopback" => Ok(NetPolicy::Loopback),
        other => Err(format!(
            "unknown --net `{other}` (expected host, deny or loopback)"
        )),
    }
}

fn parse_env(entry: &str) -> Result<(String, String), String> {
    match entry.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_string(), value.to_string())),
        _ => Err(format!("invalid --env `{entry}` (expected K=V)")),
    }
}
