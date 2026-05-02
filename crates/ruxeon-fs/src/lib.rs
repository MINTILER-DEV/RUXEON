//! Virtual filesystem placeholder for Phase 4.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootFs {
    host_root: std::path::PathBuf,
}

impl RootFs {
    pub fn new(host_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            host_root: host_root.into(),
        }
    }

    pub fn host_root(&self) -> &std::path::Path {
        &self.host_root
    }
}
