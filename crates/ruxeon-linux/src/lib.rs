//! Linux syscall layer for the user-mode runtime.

use ruxeon_core::{GuestMemory, GuestMemoryError, MemoryPermission, PAGE_SIZE};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use thiserror::Error;

const AT_FDCWD: u64 = (-100i64) as u64;
const STAT_SIZE: usize = 144;
const UTSNAME_FIELD_SIZE: usize = 65;
const UTSNAME_SIZE: usize = UTSNAME_FIELD_SIZE * 6;

const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200000;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;

const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Errno {
    Perm = 1,
    NoEnt = 2,
    Intr = 4,
    Io = 5,
    NxIo = 6,
    Badf = 9,
    Again = 11,
    NoMem = 12,
    Acces = 13,
    Fault = 14,
    Busy = 16,
    NotDir = 20,
    IsDir = 21,
    Inval = 22,
    MFile = 24,
    NoSys = 38,
    NamTooLong = 36,
}

impl Errno {
    pub const fn linux_return(self) -> i64 {
        -(self as i64)
    }
}

#[derive(Debug, Error)]
pub enum SyscallError {
    #[error("guest memory error: {0}")]
    Memory(#[from] GuestMemoryError),
    #[error("linux errno {0:?}")]
    Errno(Errno),
}

impl From<Errno> for SyscallError {
    fn from(value: Errno) -> Self {
        Self::Errno(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    Read,
    Write,
    Open,
    Close,
    Stat,
    Fstat,
    Lstat,
    Mmap,
    Mprotect,
    Munmap,
    Brk,
    Ioctl,
    Access,
    ArchPrctl,
    Getpid,
    Gettid,
    Getcwd,
    Chdir,
    Readlink,
    Uname,
    Openat,
    Newfstatat,
    RtSigaction,
    RtSigprocmask,
    SetTidAddress,
    SetRobustList,
    Prlimit64,
    Getrandom,
    Exit,
    ExitGroup,
    Other(u64),
}

impl SyscallNumber {
    pub fn raw(self) -> u64 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Open => 2,
            Self::Close => 3,
            Self::Stat => 4,
            Self::Fstat => 5,
            Self::Lstat => 6,
            Self::Mmap => 9,
            Self::Mprotect => 10,
            Self::Munmap => 11,
            Self::Brk => 12,
            Self::RtSigaction => 13,
            Self::RtSigprocmask => 14,
            Self::Ioctl => 16,
            Self::Access => 21,
            Self::ArchPrctl => 158,
            Self::Gettid => 186,
            Self::Getpid => 39,
            Self::Getcwd => 79,
            Self::Chdir => 80,
            Self::Readlink => 89,
            Self::Uname => 63,
            Self::Openat => 257,
            Self::Newfstatat => 262,
            Self::SetTidAddress => 218,
            Self::SetRobustList => 273,
            Self::Prlimit64 => 302,
            Self::Getrandom => 318,
            Self::Exit => 60,
            Self::ExitGroup => 231,
            Self::Other(number) => number,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Open => "open",
            Self::Close => "close",
            Self::Stat => "stat",
            Self::Fstat => "fstat",
            Self::Lstat => "lstat",
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
            Self::Munmap => "munmap",
            Self::Brk => "brk",
            Self::Ioctl => "ioctl",
            Self::Access => "access",
            Self::ArchPrctl => "arch_prctl",
            Self::Getpid => "getpid",
            Self::Gettid => "gettid",
            Self::Getcwd => "getcwd",
            Self::Chdir => "chdir",
            Self::Readlink => "readlink",
            Self::Uname => "uname",
            Self::Openat => "openat",
            Self::Newfstatat => "newfstatat",
            Self::RtSigaction => "rt_sigaction",
            Self::RtSigprocmask => "rt_sigprocmask",
            Self::SetTidAddress => "set_tid_address",
            Self::SetRobustList => "set_robust_list",
            Self::Prlimit64 => "prlimit64",
            Self::Getrandom => "getrandom",
            Self::Exit => "exit",
            Self::ExitGroup => "exit_group",
            Self::Other(_) => "unknown",
        }
    }
}

impl From<u64> for SyscallNumber {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Open,
            3 => Self::Close,
            4 => Self::Stat,
            5 => Self::Fstat,
            6 => Self::Lstat,
            9 => Self::Mmap,
            10 => Self::Mprotect,
            11 => Self::Munmap,
            12 => Self::Brk,
            13 => Self::RtSigaction,
            14 => Self::RtSigprocmask,
            16 => Self::Ioctl,
            21 => Self::Access,
            39 => Self::Getpid,
            60 => Self::Exit,
            63 => Self::Uname,
            79 => Self::Getcwd,
            80 => Self::Chdir,
            89 => Self::Readlink,
            158 => Self::ArchPrctl,
            186 => Self::Gettid,
            218 => Self::SetTidAddress,
            231 => Self::ExitGroup,
            257 => Self::Openat,
            262 => Self::Newfstatat,
            273 => Self::SetRobustList,
            302 => Self::Prlimit64,
            318 => Self::Getrandom,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallInput {
    pub number: u64,
    pub args: [u64; 6],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallOutcome {
    Return(i64),
    Exit(i32),
}

impl SyscallOutcome {
    pub fn return_value(self) -> i64 {
        match self {
            Self::Return(value) => value,
            Self::Exit(code) => code as i64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallTrace {
    pub number: u64,
    pub name: &'static str,
    pub args: [u64; 6],
    pub return_value: i64,
}

pub struct SyscallContext<'a> {
    pub memory: &'a mut GuestMemory,
}

#[derive(Debug)]
pub struct LinuxProcess {
    pid: u32,
    tid: u32,
    cwd: String,
    rootfs: Option<PathBuf>,
    brk_base: u64,
    brk: u64,
    mmap_next: u64,
    fs_base: u64,
    fd_table: FdTable,
    trace: Vec<SyscallTrace>,
}

impl LinuxProcess {
    pub fn new(rootfs: Option<PathBuf>) -> Self {
        Self {
            pid: 1000,
            tid: 1000,
            cwd: "/".to_string(),
            rootfs,
            brk_base: 0x0000_7000_0000_0000,
            brk: 0x0000_7000_0000_0000,
            mmap_next: 0x0000_7100_0000_0000,
            fs_base: 0,
            fd_table: FdTable::new(),
            trace: Vec::new(),
        }
    }

    pub fn fd_table(&self) -> &FdTable {
        &self.fd_table
    }

    pub fn fd_table_mut(&mut self) -> &mut FdTable {
        &mut self.fd_table
    }

    pub fn trace(&self) -> &[SyscallTrace] {
        &self.trace
    }
}

#[derive(Debug)]
pub struct SyscallDispatcher;

impl SyscallDispatcher {
    pub fn dispatch(
        process: &mut LinuxProcess,
        context: &mut SyscallContext<'_>,
        input: SyscallInput,
    ) -> SyscallOutcome {
        let number = SyscallNumber::from(input.number);
        let outcome = match Self::dispatch_inner(process, context, number, input.args) {
            Ok(outcome) => outcome,
            Err(SyscallError::Errno(errno)) => SyscallOutcome::Return(errno.linux_return()),
            Err(SyscallError::Memory(_)) => SyscallOutcome::Return(Errno::Fault.linux_return()),
        };
        process.trace.push(SyscallTrace {
            number: input.number,
            name: number.name(),
            args: input.args,
            return_value: outcome.return_value(),
        });
        outcome
    }

    fn dispatch_inner(
        process: &mut LinuxProcess,
        context: &mut SyscallContext<'_>,
        number: SyscallNumber,
        args: [u64; 6],
    ) -> Result<SyscallOutcome, SyscallError> {
        let value = match number {
            SyscallNumber::Read => {
                let fd = fd_arg(args[0])?;
                let len = usize_arg(args[2])?;
                let mut bytes = vec![0; len];
                let count = process.fd_table.read(fd, &mut bytes)?;
                context.memory.write_bytes(args[1], &bytes[..count])?;
                count as i64
            }
            SyscallNumber::Write => {
                let fd = fd_arg(args[0])?;
                let len = usize_arg(args[2])?;
                let bytes = context.memory.read_bytes(args[1], len)?;
                process.fd_table.write(fd, &bytes)? as i64
            }
            SyscallNumber::Open => {
                let path = read_c_string(context.memory, args[0])?;
                process.open_guest_path(None, &path, args[1])? as i64
            }
            SyscallNumber::Openat => {
                let path = read_c_string(context.memory, args[1])?;
                process.open_guest_path(fd_arg_allow_at_fdcwd(args[0])?, &path, args[2])? as i64
            }
            SyscallNumber::Close => {
                process.fd_table.close(fd_arg(args[0])?)?;
                0
            }
            SyscallNumber::Stat | SyscallNumber::Lstat => {
                let path = read_c_string(context.memory, args[0])?;
                let host_path = process.translate_path(None, &path)?;
                write_stat_for_path(context.memory, args[1], &host_path)?;
                0
            }
            SyscallNumber::Fstat => {
                let stat = process.fd_table.stat(fd_arg(args[0])?)?;
                write_stat(context.memory, args[1], stat)?;
                0
            }
            SyscallNumber::Newfstatat => {
                let path = read_c_string(context.memory, args[1])?;
                let host_path = process.translate_path(fd_arg_allow_at_fdcwd(args[0])?, &path)?;
                write_stat_for_path(context.memory, args[2], &host_path)?;
                0
            }
            SyscallNumber::Exit | SyscallNumber::ExitGroup => {
                return Ok(SyscallOutcome::Exit(args[0] as i32));
            }
            SyscallNumber::Brk => process.brk(context.memory, args[0])? as i64,
            SyscallNumber::Mmap => process.mmap(context.memory, args[0], args[1], args[2])? as i64,
            SyscallNumber::Munmap => {
                let size = align_up(args[1], PAGE_SIZE);
                context.memory.unmap_region(args[0], size)?;
                0
            }
            SyscallNumber::Mprotect => {
                let size = usize_arg(align_up(args[1], PAGE_SIZE))?;
                context
                    .memory
                    .protect(args[0], size, memory_permissions(args[2]))?;
                0
            }
            SyscallNumber::ArchPrctl => match args[0] {
                ARCH_SET_FS => {
                    process.fs_base = args[1];
                    0
                }
                ARCH_GET_FS => {
                    context.memory.write_u64(args[1], process.fs_base)?;
                    0
                }
                _ => return Err(Errno::Inval.into()),
            },
            SyscallNumber::Getpid => i64::from(process.pid),
            SyscallNumber::Gettid => i64::from(process.tid),
            SyscallNumber::Uname => {
                write_uname(context.memory, args[0])?;
                0
            }
            SyscallNumber::Getcwd => {
                let mut bytes = process.cwd.as_bytes().to_vec();
                bytes.push(0);
                if bytes.len() > usize_arg(args[1])? {
                    return Err(Errno::NoEnt.into());
                }
                context.memory.write_bytes(args[0], &bytes)?;
                args[0] as i64
            }
            SyscallNumber::Chdir => {
                let path = read_c_string(context.memory, args[0])?;
                let (guest, host) = process.normalize_guest_path(&path)?;
                if !host.is_dir() {
                    return Err(Errno::NoEnt.into());
                }
                process.cwd = guest;
                0
            }
            SyscallNumber::Access => {
                let path = read_c_string(context.memory, args[0])?;
                let host_path = process.translate_path(None, &path)?;
                if host_path.exists() {
                    0
                } else {
                    return Err(Errno::NoEnt.into());
                }
            }
            SyscallNumber::Readlink => {
                let path = read_c_string(context.memory, args[0])?;
                let target = if path == "/proc/self/exe" {
                    b"/proc/self/exe".to_vec()
                } else {
                    let host_path = process.translate_path(None, &path)?;
                    fs::read_link(host_path)
                        .map_err(map_io_errno)?
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec()
                };
                let len = target.len().min(usize_arg(args[2])?);
                context.memory.write_bytes(args[1], &target[..len])?;
                len as i64
            }
            SyscallNumber::Ioctl => Errno::Inval.linux_return(),
            SyscallNumber::RtSigaction
            | SyscallNumber::RtSigprocmask
            | SyscallNumber::SetRobustList
            | SyscallNumber::Prlimit64 => 0,
            SyscallNumber::SetTidAddress => i64::from(process.tid),
            SyscallNumber::Getrandom => {
                let len = usize_arg(args[1])?;
                let bytes = deterministic_random(len);
                context.memory.write_bytes(args[0], &bytes)?;
                len as i64
            }
            SyscallNumber::Other(_) => return Err(Errno::NoSys.into()),
        };
        Ok(SyscallOutcome::Return(value))
    }
}

#[derive(Debug)]
pub struct FdTable {
    entries: HashMap<i32, FdEntry>,
    next_fd: i32,
}

impl FdTable {
    pub fn new() -> Self {
        let mut entries = HashMap::new();
        entries.insert(0, FdEntry::Stdin);
        entries.insert(1, FdEntry::Stdout);
        entries.insert(2, FdEntry::Stderr);
        Self {
            entries,
            next_fd: 3,
        }
    }

    pub fn insert(&mut self, entry: FdEntry) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.entries.insert(fd, entry);
        fd
    }

    pub fn set(&mut self, fd: i32, entry: FdEntry) {
        self.next_fd = self.next_fd.max(fd + 1);
        self.entries.insert(fd, entry);
    }

    pub fn install_buffer(&mut self, fd: i32, buffer: Arc<Mutex<Vec<u8>>>) {
        self.set(fd, FdEntry::Buffer(buffer));
    }

    pub fn close(&mut self, fd: i32) -> Result<(), SyscallError> {
        if fd <= 2 {
            return Ok(());
        }
        self.entries.remove(&fd).ok_or(Errno::Badf)?;
        Ok(())
    }

    pub fn read(&mut self, fd: i32, bytes: &mut [u8]) -> Result<usize, SyscallError> {
        let entry = self.entries.get_mut(&fd).ok_or(Errno::Badf)?;
        match entry {
            FdEntry::Stdin => io::stdin().read(bytes).map_err(map_io_errno),
            FdEntry::File(file) => file.read(bytes).map_err(map_io_errno),
            FdEntry::Buffer(buffer) => {
                let mut buffer = buffer.lock().map_err(|_| Errno::Io)?;
                let count = bytes.len().min(buffer.len());
                bytes[..count].copy_from_slice(&buffer[..count]);
                buffer.drain(..count);
                Ok(count)
            }
            FdEntry::Stdout | FdEntry::Stderr | FdEntry::Directory(_) => Err(Errno::Badf.into()),
        }
    }

    pub fn write(&mut self, fd: i32, bytes: &[u8]) -> Result<usize, SyscallError> {
        let entry = self.entries.get_mut(&fd).ok_or(Errno::Badf)?;
        match entry {
            FdEntry::Stdout => {
                io::stdout().write_all(bytes).map_err(map_io_errno)?;
                io::stdout().flush().map_err(map_io_errno)?;
                Ok(bytes.len())
            }
            FdEntry::Stderr => {
                io::stderr().write_all(bytes).map_err(map_io_errno)?;
                io::stderr().flush().map_err(map_io_errno)?;
                Ok(bytes.len())
            }
            FdEntry::File(file) => file.write(bytes).map_err(map_io_errno),
            FdEntry::Buffer(buffer) => {
                buffer
                    .lock()
                    .map_err(|_| Errno::Io)?
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            FdEntry::Stdin | FdEntry::Directory(_) => Err(Errno::Badf.into()),
        }
    }

    pub fn stat(&self, fd: i32) -> Result<StatData, SyscallError> {
        let entry = self.entries.get(&fd).ok_or(Errno::Badf)?;
        match entry {
            FdEntry::File(file) => stat_from_metadata(file.metadata().map_err(map_io_errno)?),
            FdEntry::Directory(path) => write_stat_data_for_path(path),
            FdEntry::Stdin | FdEntry::Stdout | FdEntry::Stderr | FdEntry::Buffer(_) => {
                Ok(StatData::char_device())
            }
        }
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum FdEntry {
    Stdin,
    Stdout,
    Stderr,
    File(File),
    Directory(PathBuf),
    Buffer(Arc<Mutex<Vec<u8>>>),
}

impl LinuxProcess {
    fn open_guest_path(
        &mut self,
        dirfd: Option<i32>,
        path: &str,
        flags: u64,
    ) -> Result<i32, SyscallError> {
        let host_path = self.translate_path(dirfd, path)?;
        if flags & O_DIRECTORY != 0 {
            if !host_path.is_dir() {
                return Err(Errno::NotDir.into());
            }
            return Ok(self.fd_table.insert(FdEntry::Directory(host_path)));
        }

        let mut options = OpenOptions::new();
        match flags & O_ACCMODE {
            O_WRONLY => {
                options.write(true);
            }
            O_RDWR => {
                options.read(true).write(true);
            }
            _ => {
                options.read(true);
            }
        }
        if flags & O_CREAT != 0 {
            options.create(true);
        }
        if flags & O_TRUNC != 0 {
            options.truncate(true);
        }
        if flags & O_APPEND != 0 {
            options.append(true);
        }

        let mut file = options.open(&host_path).map_err(map_io_errno)?;
        if flags & O_APPEND != 0 {
            file.seek(SeekFrom::End(0)).map_err(map_io_errno)?;
        }
        Ok(self.fd_table.insert(FdEntry::File(file)))
    }

    fn brk(&mut self, memory: &mut GuestMemory, requested: u64) -> Result<u64, SyscallError> {
        if requested == 0 {
            return Ok(self.brk);
        }
        if requested < self.brk_base {
            return Ok(self.brk);
        }
        if requested > self.brk {
            let map_start = align_up(self.brk, PAGE_SIZE);
            let map_end = align_up(requested, PAGE_SIZE);
            if map_end > map_start {
                memory.map_region(
                    map_start,
                    map_end - map_start,
                    MemoryPermission::READ | MemoryPermission::WRITE,
                    Some("[brk]".to_string()),
                )?;
            }
        }
        self.brk = requested;
        Ok(self.brk)
    }

    fn mmap(
        &mut self,
        memory: &mut GuestMemory,
        requested_addr: u64,
        len: u64,
        prot: u64,
    ) -> Result<u64, SyscallError> {
        if len == 0 {
            return Err(Errno::Inval.into());
        }
        let size = align_up(len, PAGE_SIZE);
        let address = if requested_addr == 0 {
            let address = self.mmap_next;
            self.mmap_next = self.mmap_next.saturating_add(size + PAGE_SIZE);
            address
        } else {
            requested_addr
        };
        memory.map_region(
            address,
            size,
            memory_permissions(prot),
            Some("[mmap]".to_string()),
        )?;
        Ok(address)
    }

    fn translate_path(&self, dirfd: Option<i32>, path: &str) -> Result<PathBuf, SyscallError> {
        if path.is_empty() {
            return Err(Errno::NoEnt.into());
        }
        if path.starts_with('/') || dirfd.is_none() {
            let (_, host) = self.normalize_guest_path(path)?;
            return Ok(host);
        }
        let fd = dirfd.expect("checked above");
        match self.fd_table.entries.get(&fd) {
            Some(FdEntry::Directory(base)) => Ok(base.join(path.replace('/', "\\"))),
            _ => Err(Errno::Badf.into()),
        }
    }

    fn normalize_guest_path(&self, path: &str) -> Result<(String, PathBuf), SyscallError> {
        let mut parts = if path.starts_with('/') {
            Vec::new()
        } else {
            self.cwd
                .split('/')
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };

        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                value => {
                    if value.contains('\0') {
                        return Err(Errno::Inval.into());
                    }
                    parts.push(value.to_string());
                }
            }
        }

        let guest = format!("/{}", parts.join("/"));
        let host = match &self.rootfs {
            Some(rootfs) => {
                let mut host = rootfs.clone();
                for part in &parts {
                    host.push(part);
                }
                host
            }
            None => PathBuf::from(&guest),
        };
        Ok((guest, host))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatData {
    mode: u32,
    size: u64,
    blocks: u64,
}

impl StatData {
    fn regular(size: u64) -> Self {
        Self {
            mode: 0o100644,
            size,
            blocks: size.div_ceil(512),
        }
    }

    fn directory() -> Self {
        Self {
            mode: 0o040755,
            size: 0,
            blocks: 0,
        }
    }

    fn char_device() -> Self {
        Self {
            mode: 0o020666,
            size: 0,
            blocks: 0,
        }
    }
}

fn write_stat_for_path(
    memory: &mut GuestMemory,
    addr: u64,
    path: &Path,
) -> Result<(), SyscallError> {
    let data = write_stat_data_for_path(path)?;
    write_stat(memory, addr, data)
}

fn write_stat_data_for_path(path: &Path) -> Result<StatData, SyscallError> {
    stat_from_metadata(fs::metadata(path).map_err(map_io_errno)?)
}

fn stat_from_metadata(metadata: fs::Metadata) -> Result<StatData, SyscallError> {
    if metadata.is_dir() {
        Ok(StatData::directory())
    } else {
        Ok(StatData::regular(metadata.len()))
    }
}

fn write_stat(memory: &mut GuestMemory, addr: u64, data: StatData) -> Result<(), SyscallError> {
    let mut bytes = vec![0; STAT_SIZE];
    write_u64(&mut bytes, 0, 1);
    write_u64(&mut bytes, 8, 1);
    write_u64(&mut bytes, 16, 1);
    write_u32(&mut bytes, 24, data.mode);
    write_u64(&mut bytes, 48, data.size);
    write_u64(&mut bytes, 56, 4096);
    write_u64(&mut bytes, 64, data.blocks);
    memory.write_bytes(addr, &bytes)?;
    Ok(())
}

fn write_uname(memory: &mut GuestMemory, addr: u64) -> Result<(), SyscallError> {
    let mut bytes = vec![0; UTSNAME_SIZE];
    let fields = [
        "Linux",
        "ruxeon",
        "6.0.0-ruxeon",
        "#1 Ruxeon user-mode",
        "x86_64",
        "ruxeon",
    ];
    for (index, field) in fields.iter().enumerate() {
        let offset = index * UTSNAME_FIELD_SIZE;
        let raw = field.as_bytes();
        let len = raw.len().min(UTSNAME_FIELD_SIZE - 1);
        bytes[offset..offset + len].copy_from_slice(&raw[..len]);
    }
    memory.write_bytes(addr, &bytes)?;
    Ok(())
}

fn read_c_string(memory: &GuestMemory, addr: u64) -> Result<String, SyscallError> {
    let mut bytes = Vec::new();
    for offset in 0..4096u64 {
        let byte = memory.read_u8(addr + offset)?;
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| Errno::Inval.into());
        }
        bytes.push(byte);
    }
    Err(Errno::NamTooLong.into())
}

fn fd_arg(value: u64) -> Result<i32, SyscallError> {
    i32::try_from(value).map_err(|_| Errno::Badf.into())
}

fn fd_arg_allow_at_fdcwd(value: u64) -> Result<Option<i32>, SyscallError> {
    if value == AT_FDCWD {
        Ok(None)
    } else {
        Ok(Some(fd_arg(value)?))
    }
}

fn usize_arg(value: u64) -> Result<usize, SyscallError> {
    usize::try_from(value).map_err(|_| Errno::Inval.into())
}

fn memory_permissions(prot: u64) -> MemoryPermission {
    let mut permissions = MemoryPermission::empty();
    if prot & PROT_READ != 0 {
        permissions |= MemoryPermission::READ;
    }
    if prot & PROT_WRITE != 0 {
        permissions |= MemoryPermission::WRITE;
    }
    if prot & PROT_EXEC != 0 {
        permissions |= MemoryPermission::EXECUTE;
    }
    permissions
}

fn deterministic_random(len: usize) -> Vec<u8> {
    let mut state = 0x5255_5845_4f4e_u64;
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        bytes.push(state as u8);
    }
    bytes
}

fn map_io_errno(error: io::Error) -> SyscallError {
    match error.kind() {
        io::ErrorKind::NotFound => Errno::NoEnt.into(),
        io::ErrorKind::PermissionDenied => Errno::Acces.into(),
        io::ErrorKind::AlreadyExists => Errno::Busy.into(),
        io::ErrorKind::InvalidInput => Errno::Inval.into(),
        io::ErrorKind::WouldBlock => Errno::Again.into(),
        _ => Errno::Io.into(),
    }
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn align_up(value: u64, align: u64) -> u64 {
    if value == 0 {
        0
    } else {
        ((value - 1) / align + 1) * align
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_with_data(addr: u64, data: &[u8]) -> GuestMemory {
        let mut memory = GuestMemory::new();
        memory
            .map_region(
                0x1000,
                0x4000,
                MemoryPermission::READ | MemoryPermission::WRITE,
                Some("test".to_string()),
            )
            .unwrap();
        memory.write_bytes(addr, data).unwrap();
        memory
    }

    #[test]
    fn writes_stdout_to_buffer() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let mut process = LinuxProcess::new(None);
        process.fd_table_mut().install_buffer(1, buffer.clone());
        let mut memory = memory_with_data(0x1000, b"hello\n");

        let outcome = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Write.raw(),
                args: [1, 0x1000, 6, 0, 0, 0],
            },
        );

        assert_eq!(outcome, SyscallOutcome::Return(6));
        assert_eq!(&*buffer.lock().unwrap(), b"hello\n");
        assert_eq!(process.trace()[0].name, "write");
    }

    #[test]
    fn maps_and_unmaps_memory() {
        let mut process = LinuxProcess::new(None);
        let mut memory = GuestMemory::new();

        let mapped = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Mmap.raw(),
                args: [0, 4096, PROT_READ | PROT_WRITE, 0, 0, 0],
            },
        );
        let SyscallOutcome::Return(addr) = mapped else {
            panic!("expected mmap return");
        };
        assert!(addr > 0);

        memory.write_u8(addr as u64, 1).unwrap();
        let unmapped = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Munmap.raw(),
                args: [addr as u64, 4096, 0, 0, 0, 0],
            },
        );
        assert_eq!(unmapped, SyscallOutcome::Return(0));
        assert!(matches!(
            memory.read_u8(addr as u64),
            Err(GuestMemoryError::Unmapped { .. })
        ));
    }

    #[test]
    fn returns_negative_errno_for_unknown_syscall() {
        let mut process = LinuxProcess::new(None);
        let mut memory = GuestMemory::new();

        let outcome = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: 9999,
                args: [0; 6],
            },
        );

        assert_eq!(outcome, SyscallOutcome::Return(Errno::NoSys.linux_return()));
    }
}
