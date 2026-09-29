use std::sync::Arc;

use crate::{Backend, Capabilities, Result, SandboxError, SandboxSpec};

/// Holds the backends available in this process and resolves a spec to one.
#[derive(Default)]
pub struct Registry {
    backends: Vec<Arc<dyn Backend>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("backends", &self.names())
            .finish()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a backend. Registering the same name twice is a programming
    /// error and panics in debug builds; in release the later one wins.
    pub fn register(&mut self, backend: Arc<dyn Backend>) -> &mut Self {
        debug_assert!(
            !self.backends.iter().any(|b| b.name() == backend.name()),
            "backend `{}` registered twice",
            backend.name()
        );
        self.backends.retain(|b| b.name() != backend.name());
        self.backends.push(backend);
        self
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Backend>> {
        self.backends.iter().find(|b| b.name() == name).cloned()
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.backends.iter().map(|b| b.name()).collect()
    }

    pub fn list(&self) -> Vec<(Arc<dyn Backend>, Capabilities)> {
        self.backends
            .iter()
            .map(|b| (Arc::clone(b), b.capabilities()))
            .collect()
    }

    /// The strongest backend registered for this host, used when a spec does
    /// not pin one.
    pub fn best(&self) -> Result<Arc<dyn Backend>> {
        self.backends
            .iter()
            .max_by_key(|b| b.capabilities().isolation)
            .cloned()
            .ok_or_else(|| SandboxError::BackendNotFound("<any>".to_string()))
    }

    /// Resolve the backend a spec should run on: the pinned one if present,
    /// otherwise the strongest available.
    pub fn resolve(&self, spec: &SandboxSpec) -> Result<Arc<dyn Backend>> {
        match &spec.backend {
            Some(name) => self
                .get(name)
                .ok_or_else(|| SandboxError::BackendNotFound(name.clone())),
            None => self.best(),
        }
    }
}
