//! Virtual Linux filesystem and rootfs path resolver.

use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const MAX_SYMLINK_EXPANSIONS: usize = 40;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FsError {
    #[error("guest path is empty")]
    EmptyPath,
    #[error("guest path contains a Windows prefix")]
    WindowsPrefix,
    #[error("guest path contains a NUL byte")]
    NulByte,
    #[error("guest path contains too many symlink expansions")]
    TooManySymlinks,
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
        let guest = self.resolve_guest_path(cwd, path)?;
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

    fn resolve_guest_path(&self, cwd: &GuestPath, path: &str) -> Result<GuestPath, FsError> {
        let mut guest = cwd.join(path)?;
        let mut expansions = 0usize;

        loop {
            let components = guest.components().map(str::to_string).collect::<Vec<_>>();
            let mut resolved = Vec::with_capacity(components.len());
            let mut changed = false;
            let mut index = 0usize;

            while index < components.len() {
                let component = &components[index];
                let candidate_guest = guest_from_components(
                    resolved
                        .iter()
                        .cloned()
                        .chain(std::iter::once(component.clone())),
                );
                let candidate_host = self.host_path(&candidate_guest);
                match fs::symlink_metadata(&candidate_host) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        expansions += 1;
                        if expansions > MAX_SYMLINK_EXPANSIONS {
                            return Err(FsError::TooManySymlinks);
                        }

                        let target = fs::read_link(&candidate_host)
                            .unwrap_or_else(|_| PathBuf::from(component));
                        let target_text = target.to_string_lossy();
                        let parent_guest = guest_from_components(resolved.iter().cloned());
                        let mut next_guest = if target.is_absolute() {
                            GuestPath::parse(&target_text)?
                        } else {
                            parent_guest.join(&target_text)?
                        };

                        if index + 1 < components.len() {
                            let remainder = components[index + 1..].join("/");
                            next_guest = next_guest.join(&remainder)?;
                        }

                        guest = next_guest;
                        changed = true;
                        break;
                    }
                    Ok(_) => resolved.push(component.clone()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        resolved.extend(components[index..].iter().cloned());
                        index = components.len() - 1;
                    }
                    Err(_) => resolved.push(component.clone()),
                }

                index += 1;
            }

            if !changed {
                return Ok(guest_from_components(resolved));
            }
        }
    }

    fn host_path(&self, guest: &GuestPath) -> PathBuf {
        let mut host = self.host_root.clone();
        for component in guest.components() {
            host.push(component);
        }
        host
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

fn guest_from_components(components: impl IntoIterator<Item = String>) -> GuestPath {
    let parts = components.into_iter().collect::<Vec<_>>();
    if parts.is_empty() {
        GuestPath::root()
    } else {
        GuestPath {
            raw: format!("/{}", parts.join("/")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{create_dir_all, write};

    #[cfg(windows)]
    fn create_file_symlink(link: &Path, target: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[cfg(unix)]
    fn create_file_symlink(link: &Path, target: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

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

    #[test]
    fn resolves_relative_symlink_targets_inside_rootfs() {
        let root = std::env::temp_dir().join(format!("ruxeon-fs-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        create_dir_all(root.join("lib")).unwrap();
        create_dir_all(root.join("lib64")).unwrap();
        write(root.join("lib").join("ld-musl-x86_64.so.1"), b"loader").unwrap();

        if create_file_symlink(
            &root.join("lib64").join("ld-linux-x86-64.so.2"),
            Path::new("../lib/ld-musl-x86_64.so.1"),
        )
        .is_err()
        {
            let _ = fs::remove_dir_all(&root);
            return;
        }

        let rootfs = RootFs::new(&root);
        let resolved = rootfs
            .resolve(&GuestPath::root(), "/lib64/ld-linux-x86-64.so.2")
            .unwrap();

        assert_eq!(resolved.guest().as_str(), "/lib/ld-musl-x86_64.so.1");
        assert_eq!(
            resolved.host().unwrap(),
            root.join("lib").join("ld-musl-x86_64.so.1").as_path()
        );

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn resolves_symlink_targets_into_virtual_files() {
        let root =
            std::env::temp_dir().join(format!("ruxeon-fs-virtual-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        create_dir_all(&root).unwrap();

        if create_file_symlink(&root.join("cpuinfo-link"), Path::new("/proc/cpuinfo")).is_err() {
            let _ = fs::remove_dir_all(&root);
            return;
        }

        let rootfs = RootFs::new(&root);
        let resolved = rootfs.resolve(&GuestPath::root(), "/cpuinfo-link").unwrap();
        assert_eq!(resolved.virtual_file(), Some(VirtualFile::ProcCpuInfo));

        fs::remove_dir_all(&root).unwrap();
    }
}
