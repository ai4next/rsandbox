//! Internal, Unix-only plumbing shared by the `rsandbox` backends.
//!
//! This crate is an implementation detail, not part of the public API: it exists
//! so that every backend enforces budgets, deadlines and output caps the same
//! way. Anything backend-specific — namespaces, seccomp, Landlock, cgroups —
//! stays in the backend that owns it.

pub mod capture;
pub mod env;
pub mod limits;
pub mod supervise;
pub mod wait;

/// How often a supervisor reaps a child while enforcing a wall-clock deadline.
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);
