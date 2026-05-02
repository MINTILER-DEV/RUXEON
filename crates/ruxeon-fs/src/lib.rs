//! Virtual Linux filesystem and rootfs path resolver.

use std::{
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FsError {
    #[error("guest path is empty")]
    EmptyPath,
    #[error("guest path contains a Windows prefix")]
    WindowsPrefix,
    #[error("guest path contains a NUL byte")]
    NulByte,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootFs {
    host_root: PathBuf,
}

impl RootFs {
    pub fn new(host_root: impl Into<PathBuf>) -> Self {
        Self {
            host_root: host_root.into(),
        }
    }

    pub fn host_root(&self) -> &Path {
        &self.host_root
    }

    pub fn resolve(&self, cwd: &GuestPath, path: &str) -> Result<ResolvedPath, FsError> {
        let guest = cwd.join(path)?;
        if let Some(virtual_file) = VirtualFile::from_guest_path(guest.as_str()) {
            return Ok(ResolvedPath::Virtual {
                guest,
                file: virtual_file,
            });
        }

        let mut host = self.host_root.clone();
        for component in guest.components() {
            host.push(component);
        }
        Ok(ResolvedPath::Host { guest, host })
    }

    pub fn resolve_host(
        &self,
        cwd: &GuestPath,
        path: &str,
    ) -> Result<(GuestPath, PathBuf), FsError> {
        match self.resolve(cwd, path)? {
            ResolvedPath::Host { guest, host } => Ok((guest, host)),
            ResolvedPath::Virtual { guest, .. } => {
                let mut host = self.host_root.clone();
                for component in guest.components() {
                    host.push(component);
                }
                Ok((guest, host))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPath {
    raw: String,
}

impl GuestPath {
    pub fn root() -> Self {
        Self {
            raw: "/".to_string(),
        }
    }

    pub fn parse(path: &str) -> Result<Self, FsError> {
        Self::from_parts("/", path)
    }

    pub fn join(&self, path: &str) -> Result<Self, FsError> {
        Self::from_parts(&self.raw, path)
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.raw.split('/').filter(|part| !part.is_empty())
    }

    fn from_parts(cwd: &str, path: &str) -> Result<Self, FsError> {
        if path.is_empty() {
            return Err(FsError::EmptyPath);
        }
        if path.contains('\0') {
            return Err(FsError::NulByte);
        }
        if Path::new(path)
            .components()
            .any(|component| matches!(component, Component::Prefix(_)))
        {
            return Err(FsError::WindowsPrefix);
        }

        let normalized = path.replace('\\', "/");
        let mut parts = if normalized.starts_with('/') {
            Vec::new()
        } else {
            cwd.split('/')
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };

        for part in normalized.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                value => parts.push(value.to_string()),
            }
        }

        let raw = if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        };
        Ok(Self { raw })
    }
}

impl Default for GuestPath {
    fn default() -> Self {
        Self::root()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedPath {
    Host { guest: GuestPath, host: PathBuf },
    Virtual { guest: GuestPath, file: VirtualFile },
}

impl ResolvedPath {
    pub fn guest(&self) -> &GuestPath {
        match self {
            Self::Host { guest, .. } | Self::Virtual { guest, .. } => guest,
        }
    }

    pub fn host(&self) -> Option<&Path> {
        match self {
            Self::Host { host, .. } => Some(host),
            Self::Virtual { .. } => None,
        }
    }

    pub fn virtual_file(&self) -> Option<VirtualFile> {
        match self {
            Self::Virtual { file, .. } => Some(*file),
            Self::Host { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualFile {
    DevNull,
    DevZero,
    DevRandom,
    DevURandom,
    ProcSelfExe,
    ProcVersion,
    ProcCpuInfo,
    ProcMemInfo,
}

impl VirtualFile {
    pub fn from_guest_path(path: &str) -> Option<Self> {
        match path {
            "/dev/null" => Some(Self::DevNull),
            "/dev/zero" => Some(Self::DevZero),
            "/dev/random" => Some(Self::DevRandom),
            "/dev/urandom" => Some(Self::DevURandom),
            "/proc/self/exe" => Some(Self::ProcSelfExe),
            "/proc/version" => Some(Self::ProcVersion),
            "/proc/cpuinfo" => Some(Self::ProcCpuInfo),
            "/proc/meminfo" => Some(Self::ProcMemInfo),
            _ => None,
        }
    }

    pub fn read_bytes(self, proc_self_exe: &str, max_len: usize) -> Vec<u8> {
        let bytes = match self {
            Self::DevNull => Vec::new(),
            Self::DevZero => vec![0; max_len],
            Self::DevRandom | Self::DevURandom => deterministic_random(max_len),
            Self::ProcSelfExe => proc_self_exe.as_bytes().to_vec(),
            Self::ProcVersion => b"Linux version 6.0.0-ruxeon (ruxeon) #1 x86_64\n".to_vec(),
            Self::ProcCpuInfo => {
                b"processor\t: 0\nvendor_id\t: Ruxeon\nmodel name\t: Ruxeon virtual x86_64\n\n"
                    .to_vec()
            }
            Self::ProcMemInfo => {
                b"MemTotal:        1048576 kB\nMemFree:          524288 kB\n".to_vec()
            }
        };
        bytes.into_iter().take(max_len).collect()
    }

    pub fn write(self, bytes: &[u8]) -> usize {
        match self {
            Self::DevNull => bytes.len(),
            _ => 0,
        }
    }
}

fn deterministic_random(len: usize) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0x5255_5845_4f4e);
    let mut state = nanos ^ 0x5255_5845_4f4e_u64;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        bytes.push(state as u8);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_guest_paths_without_escaping_root() {
        let root = RootFs::new("C:/rootfs");
        let cwd = GuestPath::parse("/usr/bin").unwrap();

        let resolved = root.resolve(&cwd, "../../etc/passwd").unwrap();

        assert_eq!(resolved.guest().as_str(), "/etc/passwd");
        assert_eq!(resolved.host().unwrap(), Path::new("C:/rootfs/etc/passwd"));
    }

    #[test]
    fn resolves_virtual_linux_files() {
        let root = RootFs::new("C:/rootfs");
        let resolved = root.resolve(&GuestPath::root(), "/proc/cpuinfo").unwrap();

        assert_eq!(resolved.virtual_file(), Some(VirtualFile::ProcCpuInfo));
    }

    #[test]
    fn rejects_windows_prefixes() {
        assert_eq!(
            GuestPath::parse("C:/Windows").unwrap_err(),
            FsError::WindowsPrefix
        );
    }
}
