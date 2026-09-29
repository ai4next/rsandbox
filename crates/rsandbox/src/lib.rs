//! Umbrella crate for `rsandbox`.
//!
//! Re-exports the backend-agnostic API from [`rsandbox_core`] and wires up every
//! backend that works on the current host, so embedding code only needs one
//! dependency:
//!
//! ```no_run
//! use rsandbox::{ExecRequest, SandboxSpec};
//!
//! # fn main() -> rsandbox::Result<()> {
//! let spec = SandboxSpec::default();
//! let mut sandbox = rsandbox::create(&spec)?;
//! let output = sandbox.exec(&ExecRequest::new(["/bin/echo", "hello"]))?;
//! assert!(output.success());
//! # Ok(())
//! # }
//! ```

pub use rsandbox_core::*;

/// A [`Registry`] pre-populated with the backends available on this host.
///
/// Callers that want to restrict which isolation primitives may be used should
/// build their own registry and register only the backends they trust.
pub fn registry() -> Registry {
    let mut registry = Registry::new();
    rsandbox_backend_process::register(&mut registry);
    rsandbox_backend_linux::register(&mut registry);
    registry
}

/// Create a sandbox from `spec` on the strongest backend available on this host
/// (or the one the spec pins).
pub fn create(spec: &SandboxSpec) -> Result<Box<dyn Sandbox>> {
    registry().resolve(spec)?.create(spec)
}
