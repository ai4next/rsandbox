//! Core abstractions for `rsandbox`: a secure, lightweight sandbox runtime aimed
//! at large-scale agent workloads.
//!
//! This crate is deliberately backend-agnostic. A [`Backend`] turns a declarative
//! [`SandboxSpec`] into an isolated [`Sandbox`]; a [`Registry`] picks the strongest
//! backend available on the current host. Concrete backends live in their own
//! crates (`rsandbox-backend-process`, `rsandbox-backend-linux`, …) so new
//! isolation primitives (WASM, microVM) can be added without touching this crate.

mod backend;
mod error;
mod exec;
mod registry;
mod spec;

pub use backend::{Backend, Capabilities, IsolationLevel, Sandbox, SandboxState};
pub use error::{Result, SandboxError};
pub use exec::{ExecOutput, ExecRequest, ExitStatus};
pub use registry::Registry;
pub use spec::{
    EnvPolicy, FsPolicy, Mount, MountKind, NetPolicy, ResourceLimits, SandboxId, SandboxSpec,
};
