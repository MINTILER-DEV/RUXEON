//! Linux syscall layer for the user-mode runtime.

use ruxeon_core::{GuestMemory, GuestMemoryError, MemoryPermission, PAGE_SIZE};
use ruxeon_cpu::Registers;
use ruxeon_fs::{FsError, GuestPath, ResolvedPath, RootFs, VirtualFile};
use ruxeon_host::TerminalSize;
use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const AT_FDCWD: u64 = (-100i64) as u64;
const AT_REMOVEDIR: u64 = 0x200;
const STAT_SIZE: usize = 144;
const UTSNAME_FIELD_SIZE: usize = 65;
const UTSNAME_SIZE: usize = UTSNAME_FIELD_SIZE * 6;

const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_NONBLOCK: u64 = 0o4000;
const O_DIRECTORY: u64 = 0o200000;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;

const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;

const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;
const FD_CLOEXEC: u64 = 1;

const POLLIN: i16 = 0x001;
const POLLOUT: i16 = 0x004;
const POLLNVAL: i16 = 0x020;

const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;

const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TIOCGPGRP: u64 = 0x540f;
const TIOCSPGRP: u64 = 0x5410;

const TERMIOS_SIZE: usize = 60;
const NCCS: usize = 32;
const BRKINT: u32 = 0x0002;
const ICRNL: u32 = 0x0100;
const IXON: u32 = 0x0400;
const OPOST: u32 = 0x0001;
const ONLCR: u32 = 0x0004;
const B38400: u32 = 0x000f;
const CS8: u32 = 0x0030;
const CREAD: u32 = 0x0080;
const ISIG: u32 = 0x0001;
const ICANON: u32 = 0x0002;
const ECHO: u32 = 0x0008;
const ECHOE: u32 = 0x0010;
const ECHOK: u32 = 0x0020;
const IEXTEN: u32 = 0x8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Errno {
    Perm = 1,
    NoEnt = 2,
    Intr = 4,
    Io = 5,
    NxIo = 6,
    Badf = 9,
    Child = 10,
    Again = 11,
    NoMem = 12,
    Acces = 13,
    Fault = 14,
    Busy = 16,
    Exist = 17,
    NotDir = 20,
    IsDir = 21,
    Inval = 22,
    MFile = 24,
    NoTty = 25,
    Pipe = 32,
    Loop = 40,
    NoSys = 38,
    NoData = 61,
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
    Readv,
    Writev,
    Open,
    Close,
    Stat,
    Fstat,
    Lstat,
    Mmap,
    Mprotect,
    Munmap,
    Brk,
    RtSigreturn,
    Ioctl,
    Pipe,
    Select,
    Poll,
    Dup,
    Dup2,
    Nanosleep,
    Clone,
    Fork,
    VFork,
    Execve,
    Wait4,
    Kill,
    Fcntl,
    Mkdir,
    Rmdir,
    Unlink,
    Getdents,
    Times,
    Sysinfo,
    Access,
    ArchPrctl,
    Getpid,
    Sendfile,
    Getppid,
    Gettid,
    Getuid,
    Getgid,
    Setpgid,
    Getpgid,
    Geteuid,
    Getegid,
    Getcwd,
    Chdir,
    Readlink,
    Uname,
    Sigaltstack,
    Getdents64,
    ClockGettime,
    Pselect6,
    Ppoll,
    Dup3,
    Pipe2,
    Openat,
    Mkdirat,
    Unlinkat,
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
            Self::Readv => 19,
            Self::Writev => 20,
            Self::Open => 2,
            Self::Close => 3,
            Self::Stat => 4,
            Self::Fstat => 5,
            Self::Lstat => 6,
            Self::Poll => 7,
            Self::Mmap => 9,
            Self::Mprotect => 10,
            Self::Munmap => 11,
            Self::Brk => 12,
            Self::RtSigreturn => 15,
            Self::RtSigaction => 13,
            Self::RtSigprocmask => 14,
            Self::Ioctl => 16,
            Self::Pipe => 22,
            Self::Select => 23,
            Self::Dup => 32,
            Self::Dup2 => 33,
            Self::Nanosleep => 35,
            Self::Clone => 56,
            Self::Fork => 57,
            Self::VFork => 58,
            Self::Execve => 59,
            Self::Wait4 => 61,
            Self::Kill => 62,
            Self::Fcntl => 72,
            Self::Mkdir => 83,
            Self::Rmdir => 84,
            Self::Unlink => 87,
            Self::Getdents => 78,
            Self::Sysinfo => 99,
            Self::Times => 100,
            Self::Getuid => 102,
            Self::Getgid => 104,
            Self::Geteuid => 107,
            Self::Getegid => 108,
            Self::Setpgid => 109,
            Self::Getppid => 110,
            Self::Getpgid => 121,
            Self::Sigaltstack => 131,
            Self::Access => 21,
            Self::ArchPrctl => 158,
            Self::Gettid => 186,
            Self::Getpid => 39,
            Self::Sendfile => 40,
            Self::Getcwd => 79,
            Self::Chdir => 80,
            Self::Readlink => 89,
            Self::Uname => 63,
            Self::Getdents64 => 217,
            Self::ClockGettime => 228,
            Self::Openat => 257,
            Self::Mkdirat => 258,
            Self::Unlinkat => 263,
            Self::Newfstatat => 262,
            Self::Pselect6 => 270,
            Self::Ppoll => 271,
            Self::SetTidAddress => 218,
            Self::SetRobustList => 273,
            Self::Dup3 => 292,
            Self::Pipe2 => 293,
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
            Self::Readv => "readv",
            Self::Writev => "writev",
            Self::Open => "open",
            Self::Close => "close",
            Self::Stat => "stat",
            Self::Fstat => "fstat",
            Self::Lstat => "lstat",
            Self::Mmap => "mmap",
            Self::Mprotect => "mprotect",
            Self::Munmap => "munmap",
            Self::Brk => "brk",
            Self::RtSigreturn => "rt_sigreturn",
            Self::Ioctl => "ioctl",
            Self::Pipe => "pipe",
            Self::Select => "select",
            Self::Poll => "poll",
            Self::Dup => "dup",
            Self::Dup2 => "dup2",
            Self::Nanosleep => "nanosleep",
            Self::Clone => "clone",
            Self::Fork => "fork",
            Self::VFork => "vfork",
            Self::Execve => "execve",
            Self::Wait4 => "wait4",
            Self::Kill => "kill",
            Self::Fcntl => "fcntl",
            Self::Mkdir => "mkdir",
            Self::Rmdir => "rmdir",
            Self::Unlink => "unlink",
            Self::Getdents => "getdents",
            Self::Times => "times",
            Self::Sysinfo => "sysinfo",
            Self::Access => "access",
            Self::ArchPrctl => "arch_prctl",
            Self::Getpid => "getpid",
            Self::Sendfile => "sendfile",
            Self::Getppid => "getppid",
            Self::Gettid => "gettid",
            Self::Getuid => "getuid",
            Self::Getgid => "getgid",
            Self::Setpgid => "setpgid",
            Self::Getpgid => "getpgid",
            Self::Geteuid => "geteuid",
            Self::Getegid => "getegid",
            Self::Getcwd => "getcwd",
            Self::Chdir => "chdir",
            Self::Readlink => "readlink",
            Self::Uname => "uname",
            Self::Sigaltstack => "sigaltstack",
            Self::Getdents64 => "getdents64",
            Self::ClockGettime => "clock_gettime",
            Self::Pselect6 => "pselect6",
            Self::Ppoll => "ppoll",
            Self::Dup3 => "dup3",
            Self::Pipe2 => "pipe2",
            Self::Openat => "openat",
            Self::Mkdirat => "mkdirat",
            Self::Unlinkat => "unlinkat",
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
            19 => Self::Readv,
            20 => Self::Writev,
            2 => Self::Open,
            3 => Self::Close,
            4 => Self::Stat,
            5 => Self::Fstat,
            6 => Self::Lstat,
            7 => Self::Poll,
            9 => Self::Mmap,
            10 => Self::Mprotect,
            11 => Self::Munmap,
            12 => Self::Brk,
            13 => Self::RtSigaction,
            14 => Self::RtSigprocmask,
            15 => Self::RtSigreturn,
            16 => Self::Ioctl,
            21 => Self::Access,
            22 => Self::Pipe,
            23 => Self::Select,
            32 => Self::Dup,
            33 => Self::Dup2,
            35 => Self::Nanosleep,
            39 => Self::Getpid,
            40 => Self::Sendfile,
            56 => Self::Clone,
            57 => Self::Fork,
            58 => Self::VFork,
            59 => Self::Execve,
            60 => Self::Exit,
            61 => Self::Wait4,
            62 => Self::Kill,
            63 => Self::Uname,
            72 => Self::Fcntl,
            83 => Self::Mkdir,
            84 => Self::Rmdir,
            87 => Self::Unlink,
            78 => Self::Getdents,
            79 => Self::Getcwd,
            80 => Self::Chdir,
            89 => Self::Readlink,
            99 => Self::Sysinfo,
            100 => Self::Times,
            102 => Self::Getuid,
            104 => Self::Getgid,
            107 => Self::Geteuid,
            108 => Self::Getegid,
            109 => Self::Setpgid,
            110 => Self::Getppid,
            121 => Self::Getpgid,
            131 => Self::Sigaltstack,
            158 => Self::ArchPrctl,
            186 => Self::Gettid,
            217 => Self::Getdents64,
            218 => Self::SetTidAddress,
            228 => Self::ClockGettime,
            231 => Self::ExitGroup,
            257 => Self::Openat,
            258 => Self::Mkdirat,
            263 => Self::Unlinkat,
            262 => Self::Newfstatat,
            270 => Self::Pselect6,
            271 => Self::Ppoll,
            273 => Self::SetRobustList,
            292 => Self::Dup3,
            293 => Self::Pipe2,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallOutcome {
    Return(i64),
    Blocked,
    Exit(i32),
    Execve(ExecveRequest),
}

impl SyscallOutcome {
    pub fn return_value(&self) -> i64 {
        match self {
            Self::Return(value) => *value,
            Self::Blocked => 0,
            Self::Exit(code) => *code as i64,
            Self::Execve(_) => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecveRequest {
    pub guest_path: String,
    pub host_path: PathBuf,
    pub rootfs: Option<PathBuf>,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
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
    ppid: u32,
    pgid: u32,
    next_child_pid: u32,
    cwd: GuestPath,
    rootfs: Option<RootFs>,
    executable_path: String,
    brk_base: u64,
    brk: u64,
    mmap_next: u64,
    fs_base: u64,
    fd_table: FdTable,
    terminal: TerminalState,
    trace: Vec<SyscallTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalState {
    termios: LinuxTermios,
    winsize: LinuxWinsize,
    winsize_overridden: bool,
}

impl TerminalState {
    fn write_termios(&mut self, memory: &mut GuestMemory, addr: u64) -> Result<(), SyscallError> {
        self.termios.write_to_memory(memory, addr)
    }

    fn read_termios(&mut self, memory: &GuestMemory, addr: u64) -> Result<(), SyscallError> {
        self.termios = LinuxTermios::read_from_memory(memory, addr)?;
        Ok(())
    }

    fn write_winsize(&mut self, memory: &mut GuestMemory, addr: u64) -> Result<(), SyscallError> {
        self.current_winsize().write_to_memory(memory, addr)
    }

    fn read_winsize(&mut self, memory: &GuestMemory, addr: u64) -> Result<(), SyscallError> {
        self.winsize = LinuxWinsize::read_from_memory(memory, addr)?;
        self.winsize_overridden = true;
        Ok(())
    }

    fn apply_host_mode(&self) -> Result<(), SyscallError> {
        ruxeon_host::set_raw_mode(self.termios.raw_mode()).map_err(map_io_errno)?;
        Ok(())
    }

    fn current_winsize(&self) -> LinuxWinsize {
        if self.winsize_overridden {
            return self.winsize;
        }
        LinuxWinsize::from_host(ruxeon_host::terminal_size())
    }
}

impl Default for TerminalState {
    fn default() -> Self {
        Self {
            termios: LinuxTermios::default(),
            winsize: LinuxWinsize::from_host(ruxeon_host::terminal_size()),
            winsize_overridden: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxTermios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; NCCS],
    ispeed: u32,
    ospeed: u32,
}

impl LinuxTermios {
    fn read_from_memory(memory: &GuestMemory, addr: u64) -> Result<Self, SyscallError> {
        let bytes = memory.read_bytes(addr, TERMIOS_SIZE)?;
        let mut cc = [0; NCCS];
        cc.copy_from_slice(&bytes[17..17 + NCCS]);
        Ok(Self {
            iflag: u32::from_le_bytes(bytes[0..4].try_into().expect("fixed termios field")),
            oflag: u32::from_le_bytes(bytes[4..8].try_into().expect("fixed termios field")),
            cflag: u32::from_le_bytes(bytes[8..12].try_into().expect("fixed termios field")),
            lflag: u32::from_le_bytes(bytes[12..16].try_into().expect("fixed termios field")),
            line: bytes[16],
            cc,
            ispeed: u32::from_le_bytes(bytes[52..56].try_into().expect("fixed termios field")),
            ospeed: u32::from_le_bytes(bytes[56..60].try_into().expect("fixed termios field")),
        })
    }

    fn write_to_memory(&self, memory: &mut GuestMemory, addr: u64) -> Result<(), SyscallError> {
        let mut bytes = [0; TERMIOS_SIZE];
        bytes[0..4].copy_from_slice(&self.iflag.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.oflag.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.cflag.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.lflag.to_le_bytes());
        bytes[16] = self.line;
        bytes[17..17 + NCCS].copy_from_slice(&self.cc);
        bytes[52..56].copy_from_slice(&self.ispeed.to_le_bytes());
        bytes[56..60].copy_from_slice(&self.ospeed.to_le_bytes());
        memory.write_bytes(addr, &bytes)?;
        Ok(())
    }

    fn raw_mode(&self) -> bool {
        self.lflag & ICANON == 0
    }
}

impl Default for LinuxTermios {
    fn default() -> Self {
        let mut cc = [0; NCCS];
        cc[0] = 3;
        cc[1] = 28;
        cc[2] = 127;
        cc[3] = 21;
        cc[4] = 4;
        cc[5] = 0;
        cc[6] = 1;
        cc[8] = 17;
        cc[9] = 19;
        cc[10] = 26;
        cc[12] = 18;
        cc[13] = 15;
        cc[14] = 23;
        cc[15] = 22;
        Self {
            iflag: BRKINT | ICRNL | IXON,
            oflag: OPOST | ONLCR,
            cflag: B38400 | CS8 | CREAD,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN,
            line: 0,
            cc,
            ispeed: B38400,
            ospeed: B38400,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxWinsize {
    rows: u16,
    cols: u16,
    xpixel: u16,
    ypixel: u16,
}

impl LinuxWinsize {
    fn from_host(size: Option<TerminalSize>) -> Self {
        let size = size.unwrap_or(TerminalSize {
            rows: 24,
            cols: 80,
            xpixel: 0,
            ypixel: 0,
        });
        Self {
            rows: size.rows.max(1),
            cols: size.cols.max(1),
            xpixel: size.xpixel,
            ypixel: size.ypixel,
        }
    }

    fn read_from_memory(memory: &GuestMemory, addr: u64) -> Result<Self, SyscallError> {
        Ok(Self {
            rows: memory.read_u16(addr)?,
            cols: memory.read_u16(addr + 2)?,
            xpixel: memory.read_u16(addr + 4)?,
            ypixel: memory.read_u16(addr + 6)?,
        })
    }

    fn write_to_memory(self, memory: &mut GuestMemory, addr: u64) -> Result<(), SyscallError> {
        memory.write_u16(addr, self.rows)?;
        memory.write_u16(addr + 2, self.cols)?;
        memory.write_u16(addr + 4, self.xpixel)?;
        memory.write_u16(addr + 6, self.ypixel)?;
        Ok(())
    }
}

impl LinuxProcess {
    pub fn new(rootfs: Option<PathBuf>) -> Self {
        Self::with_executable(rootfs, "/proc/self/exe")
    }

    pub fn with_executable(rootfs: Option<PathBuf>, executable_path: impl Into<String>) -> Self {
        Self {
            pid: 1000,
            tid: 1000,
            ppid: 1,
            pgid: 1000,
            next_child_pid: 1001,
            cwd: GuestPath::root(),
            rootfs: rootfs.map(RootFs::new),
            executable_path: executable_path.into(),
            brk_base: 0x0000_7000_0000_0000,
            brk: 0x0000_7000_0000_0000,
            mmap_next: 0x0000_7100_0000_0000,
            fs_base: 0,
            fd_table: FdTable::new(),
            terminal: TerminalState::default(),
            trace: Vec::new(),
        }
    }

    pub fn fd_table(&self) -> &FdTable {
        &self.fd_table
    }

    pub fn fd_table_mut(&mut self) -> &mut FdTable {
        &mut self.fd_table
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn tid(&self) -> u32 {
        self.tid
    }

    pub fn ppid(&self) -> u32 {
        self.ppid
    }

    pub fn pgid(&self) -> u32 {
        self.pgid
    }

    pub fn fs_base(&self) -> u64 {
        self.fs_base
    }

    pub fn trace(&self) -> &[SyscallTrace] {
        &self.trace
    }

    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    pub fn apply_exec(&mut self, executable_path: impl Into<String>) {
        self.executable_path = executable_path.into();
        self.fd_table.close_on_exec();
        self.fs_base = 0;
    }

    fn try_clone_for_child(&self, child_pid: u32) -> Result<Self, SyscallError> {
        Ok(Self {
            pid: child_pid,
            tid: child_pid,
            ppid: self.pid,
            pgid: self.pgid,
            next_child_pid: child_pid + 1,
            cwd: self.cwd.clone(),
            rootfs: self.rootfs.clone(),
            executable_path: self.executable_path.clone(),
            brk_base: self.brk_base,
            brk: self.brk,
            mmap_next: self.mmap_next,
            fs_base: self.fs_base,
            fd_table: self.fd_table.duplicate_all()?,
            terminal: self.terminal.clone(),
            trace: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Waiting,
    Exited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    pub code: i32,
}

impl ExitStatus {
    pub fn wait_status(self) -> u32 {
        ((self.code as u32) & 0xff) << 8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignalState {
    pending: Vec<i32>,
}

impl SignalState {
    pub fn pending(&self) -> &[i32] {
        &self.pending
    }

    pub fn enqueue(&mut self, signal: i32) {
        self.pending.push(signal);
    }

    pub fn take_next(&mut self) -> Option<i32> {
        if self.pending.is_empty() {
            None
        } else {
            Some(self.pending.remove(0))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxThread {
    pub tid: ThreadId,
    pub process_id: ProcessId,
    pub registers: Registers,
    pub state: ProcessState,
}

#[derive(Debug)]
pub struct ProcessRecord {
    pub process: LinuxProcess,
    pub memory: GuestMemory,
    pub threads: HashMap<ThreadId, LinuxThread>,
    pub parent: Option<ProcessId>,
    pub children: Vec<ProcessId>,
    pub state: ProcessState,
    pub exit_status: Option<ExitStatus>,
    pub signal_state: SignalState,
}

impl ProcessRecord {
    pub fn main_thread_registers(&self) -> Option<Registers> {
        let tid = ThreadId(self.process.tid);
        self.threads.get(&tid).map(|thread| thread.registers)
    }

    pub fn set_main_thread_registers(&mut self, registers: Registers) {
        let tid = ThreadId(self.process.tid);
        if let Some(thread) = self.threads.get_mut(&tid) {
            thread.registers = registers;
        }
    }

    pub fn mark_exited(&mut self, code: i32) {
        self.state = ProcessState::Exited;
        self.exit_status = Some(ExitStatus { code });
        for thread in self.threads.values_mut() {
            thread.state = ProcessState::Exited;
        }
    }
}

#[derive(Debug, Default)]
pub struct WaitQueue {
    exited: VecDeque<(ProcessId, ExitStatus)>,
}

impl WaitQueue {
    pub fn push(&mut self, pid: ProcessId, status: ExitStatus) {
        self.exited.push_back((pid, status));
    }

    pub fn pop_matching(
        &mut self,
        requested: Option<ProcessId>,
    ) -> Option<(ProcessId, ExitStatus)> {
        let index = self
            .exited
            .iter()
            .position(|(pid, _)| requested.map(|requested| requested == *pid).unwrap_or(true))?;
        self.exited.remove(index)
    }
}

#[derive(Debug, Default)]
pub struct ProcessTable {
    records: HashMap<ProcessId, ProcessRecord>,
    wait_queues: HashMap<ProcessId, WaitQueue>,
    next_pid: u32,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            wait_queues: HashMap::new(),
            next_pid: 1000,
        }
    }

    pub fn insert_initial(
        &mut self,
        process: LinuxProcess,
        memory: GuestMemory,
        registers: Registers,
    ) -> ProcessId {
        let pid = ProcessId(process.pid);
        self.next_pid = self.next_pid.max(process.pid + 1);
        let tid = ThreadId(process.tid);
        let mut threads = HashMap::new();
        threads.insert(
            tid,
            LinuxThread {
                tid,
                process_id: pid,
                registers,
                state: ProcessState::Runnable,
            },
        );
        self.records.insert(
            pid,
            ProcessRecord {
                process,
                memory,
                threads,
                parent: None,
                children: Vec::new(),
                state: ProcessState::Runnable,
                exit_status: None,
                signal_state: SignalState::default(),
            },
        );
        self.wait_queues.entry(pid).or_default();
        pid
    }

    pub fn records(&self) -> &HashMap<ProcessId, ProcessRecord> {
        &self.records
    }

    pub fn get(&self, pid: ProcessId) -> Option<&ProcessRecord> {
        self.records.get(&pid)
    }

    pub fn get_mut(&mut self, pid: ProcessId) -> Option<&mut ProcessRecord> {
        self.records.get_mut(&pid)
    }

    pub fn take(&mut self, pid: ProcessId) -> Option<ProcessRecord> {
        self.records.remove(&pid)
    }

    pub fn insert_record(&mut self, pid: ProcessId, record: ProcessRecord) {
        self.records.insert(pid, record);
    }

    pub fn fork_from_process(
        &mut self,
        parent: &LinuxProcess,
        memory: &GuestMemory,
        registers: Registers,
    ) -> Result<ProcessId, SyscallError> {
        let child_pid = self.allocate_pid();
        let child_process = parent.try_clone_for_child(child_pid.0)?;
        let mut child_registers = registers;
        child_registers.rax = 0;
        let tid = ThreadId(child_process.tid);
        let mut threads = HashMap::new();
        threads.insert(
            tid,
            LinuxThread {
                tid,
                process_id: child_pid,
                registers: child_registers,
                state: ProcessState::Runnable,
            },
        );
        self.records.insert(
            child_pid,
            ProcessRecord {
                process: child_process,
                memory: memory.clone(),
                threads,
                parent: Some(ProcessId(parent.pid)),
                children: Vec::new(),
                state: ProcessState::Runnable,
                exit_status: None,
                signal_state: SignalState::default(),
            },
        );
        self.wait_queues.entry(child_pid).or_default();
        self.wait_queues.entry(ProcessId(parent.pid)).or_default();
        if let Some(parent_record) = self.records.get_mut(&ProcessId(parent.pid)) {
            parent_record.children.push(child_pid);
        }
        Ok(child_pid)
    }

    pub fn exit_process(&mut self, pid: ProcessId, code: i32) {
        let status = ExitStatus { code };
        let parent = self.records.get(&pid).and_then(|record| record.parent);
        if let Some(record) = self.records.get_mut(&pid) {
            record.state = ProcessState::Exited;
            record.exit_status = Some(status);
            for thread in record.threads.values_mut() {
                thread.state = ProcessState::Exited;
            }
        }
        if let Some(parent) = parent {
            self.wait_queues
                .entry(parent)
                .or_default()
                .push(pid, status);
            if let Some(parent_record) = self.records.get_mut(&parent) {
                parent_record.state = ProcessState::Runnable;
                for thread in parent_record.threads.values_mut() {
                    if thread.state == ProcessState::Waiting {
                        thread.state = ProcessState::Runnable;
                    }
                }
            }
        }
    }

    pub fn record_exit(&mut self, pid: ProcessId, parent: Option<ProcessId>, code: i32) {
        self.exit_process(pid, code);
        if let Some(parent) = parent {
            let already_queued = self
                .wait_queues
                .get(&parent)
                .map(|queue| {
                    queue
                        .exited
                        .iter()
                        .any(|(queued_pid, _)| *queued_pid == pid)
                })
                .unwrap_or(false);
            if !already_queued {
                self.wait_queues
                    .entry(parent)
                    .or_default()
                    .push(pid, ExitStatus { code });
            }
            if let Some(parent_record) = self.records.get_mut(&parent) {
                parent_record.state = ProcessState::Runnable;
                for thread in parent_record.threads.values_mut() {
                    if thread.state == ProcessState::Waiting {
                        thread.state = ProcessState::Runnable;
                    }
                }
            }
        }
    }

    pub fn wait4(
        &mut self,
        parent: ProcessId,
        requested: Option<ProcessId>,
    ) -> Option<(ProcessId, ExitStatus)> {
        let waited = self
            .wait_queues
            .get_mut(&parent)
            .and_then(|queue| queue.pop_matching(requested));
        if let Some((pid, status)) = waited {
            self.records.remove(&pid);
            self.wait_queues.remove(&pid);
            if let Some(parent_record) = self.records.get_mut(&parent) {
                parent_record.children.retain(|child| *child != pid);
            }
            Some((pid, status))
        } else {
            None
        }
    }

    pub fn has_child(&self, parent: ProcessId, requested: Option<ProcessId>) -> bool {
        self.records.iter().any(|(pid, record)| {
            record.parent == Some(parent)
                && requested
                    .map(|requested_pid| requested_pid == *pid)
                    .unwrap_or(true)
        })
    }

    fn allocate_pid(&mut self) -> ProcessId {
        loop {
            let pid = ProcessId(self.next_pid);
            self.next_pid += 1;
            if !self.records.contains_key(&pid) {
                return pid;
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct Scheduler {
    run_queue: VecDeque<(ProcessId, ThreadId)>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, pid: ProcessId, tid: ThreadId) {
        if !self.run_queue.contains(&(pid, tid)) {
            self.run_queue.push_back((pid, tid));
        }
    }

    pub fn enqueue_process(&mut self, record: &ProcessRecord) {
        for thread in record.threads.values() {
            if thread.state == ProcessState::Runnable {
                self.enqueue(thread.process_id, thread.tid);
            }
        }
    }

    pub fn next_thread(&mut self, table: &ProcessTable) -> Option<(ProcessId, ThreadId)> {
        while let Some((pid, tid)) = self.run_queue.pop_front() {
            let runnable = table
                .get(pid)
                .and_then(|record| record.threads.get(&tid))
                .map(|thread| thread.state == ProcessState::Runnable)
                .unwrap_or(false);
            if runnable {
                self.run_queue.push_back((pid, tid));
                return Some((pid, tid));
            }
        }
        None
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
        Self::dispatch_with_process_model(process, context, input, None, None)
    }

    pub fn dispatch_with_process_model(
        process: &mut LinuxProcess,
        context: &mut SyscallContext<'_>,
        input: SyscallInput,
        process_table: Option<&mut ProcessTable>,
        registers: Option<Registers>,
    ) -> SyscallOutcome {
        let number = SyscallNumber::from(input.number);
        let outcome = match Self::dispatch_inner(
            process,
            context,
            number,
            input.args,
            process_table,
            registers,
        ) {
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
        process_table: Option<&mut ProcessTable>,
        registers: Option<Registers>,
    ) -> Result<SyscallOutcome, SyscallError> {
        let mut process_table = process_table;
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
            SyscallNumber::Writev => writev(
                process,
                context.memory,
                fd_arg(args[0])?,
                args[1],
                usize_arg(args[2])?,
            )?,
            SyscallNumber::Readv => readv(
                process,
                context.memory,
                fd_arg(args[0])?,
                args[1],
                usize_arg(args[2])?,
            )?,
            SyscallNumber::Sendfile => sendfile(
                process,
                context.memory,
                fd_arg(args[0])?,
                fd_arg(args[1])?,
                args[2],
                usize_arg(args[3])?,
            )?,
            SyscallNumber::Open => {
                let path = read_c_string(context.memory, args[0])?;
                process.open_guest_path(None, &path, args[1])? as i64
            }
            SyscallNumber::Mkdir => {
                let path = read_c_string(context.memory, args[0])?;
                process.mkdir_guest_path(None, &path)? as i64
            }
            SyscallNumber::Rmdir => {
                let path = read_c_string(context.memory, args[0])?;
                process.remove_guest_path(None, &path, true)? as i64
            }
            SyscallNumber::Unlink => {
                let path = read_c_string(context.memory, args[0])?;
                process.remove_guest_path(None, &path, false)? as i64
            }
            SyscallNumber::Openat => {
                let path = read_c_string(context.memory, args[1])?;
                process.open_guest_path(fd_arg_allow_at_fdcwd(args[0])?, &path, args[2])? as i64
            }
            SyscallNumber::Mkdirat => {
                let path = read_c_string(context.memory, args[1])?;
                process.mkdir_guest_path(fd_arg_allow_at_fdcwd(args[0])?, &path)? as i64
            }
            SyscallNumber::Unlinkat => {
                let path = read_c_string(context.memory, args[1])?;
                let remove_dir = args[2] & AT_REMOVEDIR != 0;
                process.remove_guest_path(fd_arg_allow_at_fdcwd(args[0])?, &path, remove_dir)?
                    as i64
            }
            SyscallNumber::Close => {
                process.fd_table.close(fd_arg(args[0])?)?;
                0
            }
            SyscallNumber::Pipe | SyscallNumber::Pipe2 => {
                let close_on_exec =
                    matches!(number, SyscallNumber::Pipe2) && args[1] & 0o2000000 != 0;
                let (read_fd, write_fd) = process.fd_table.pipe(close_on_exec);
                context.memory.write_u32(args[0], read_fd as u32)?;
                context.memory.write_u32(args[0] + 4, write_fd as u32)?;
                0
            }
            SyscallNumber::Dup => {
                i64::from(process.fd_table.duplicate(fd_arg(args[0])?, 0, false)?)
            }
            SyscallNumber::Dup2 => i64::from(process.fd_table.duplicate_to(
                fd_arg(args[0])?,
                fd_arg(args[1])?,
                false,
            )?),
            SyscallNumber::Dup3 => {
                if args[0] == args[1] {
                    return Err(Errno::Inval.into());
                }
                i64::from(process.fd_table.duplicate_to(
                    fd_arg(args[0])?,
                    fd_arg(args[1])?,
                    args[2] & 0o2000000 != 0,
                )?)
            }
            SyscallNumber::Fcntl => process.fd_table.fcntl(fd_arg(args[0])?, args[1], args[2])?,
            SyscallNumber::Getdents | SyscallNumber::Getdents64 => {
                let fd = fd_arg(args[0])?;
                let len = usize_arg(args[2])?;
                let mut bytes = vec![0; len];
                let count = process.fd_table.getdents64(fd, &mut bytes)?;
                context.memory.write_bytes(args[1], &bytes[..count])?;
                count as i64
            }
            SyscallNumber::Stat | SyscallNumber::Lstat => {
                let path = read_c_string(context.memory, args[0])?;
                process.write_stat_for_guest_path(context.memory, None, &path, args[1])?;
                0
            }
            SyscallNumber::Fstat => {
                let stat = process.fd_table.stat(fd_arg(args[0])?)?;
                write_stat(context.memory, args[1], stat)?;
                0
            }
            SyscallNumber::Newfstatat => {
                let path = read_c_string(context.memory, args[1])?;
                process.write_stat_for_guest_path(
                    context.memory,
                    fd_arg_allow_at_fdcwd(args[0])?,
                    &path,
                    args[2],
                )?;
                0
            }
            SyscallNumber::Exit | SyscallNumber::ExitGroup => {
                if let Some(table) = process_table.as_deref_mut() {
                    table.exit_process(ProcessId(process.pid), args[0] as i32);
                }
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
            SyscallNumber::Getppid => i64::from(process.ppid),
            SyscallNumber::Gettid => i64::from(process.tid),
            SyscallNumber::Getuid
            | SyscallNumber::Getgid
            | SyscallNumber::Geteuid
            | SyscallNumber::Getegid => 0,
            SyscallNumber::Setpgid => {
                process.pgid = if args[1] == 0 {
                    process.pid
                } else {
                    args[1] as u32
                };
                0
            }
            SyscallNumber::Getpgid => i64::from(process.pgid),
            SyscallNumber::Uname => {
                write_uname(context.memory, args[0])?;
                0
            }
            SyscallNumber::Getcwd => {
                let mut bytes = process.cwd.as_str().as_bytes().to_vec();
                bytes.push(0);
                if bytes.len() > usize_arg(args[1])? {
                    return Err(Errno::NoEnt.into());
                }
                context.memory.write_bytes(args[0], &bytes)?;
                args[0] as i64
            }
            SyscallNumber::Chdir => {
                let path = read_c_string(context.memory, args[0])?;
                let resolved = process.resolve_path(None, &path)?;
                let Some(host) = resolved.host() else {
                    return Err(Errno::NotDir.into());
                };
                if !host.is_dir() {
                    return Err(Errno::NoEnt.into());
                }
                process.cwd = resolved.guest().clone();
                0
            }
            SyscallNumber::Access => {
                let path = read_c_string(context.memory, args[0])?;
                let resolved = process.resolve_path(None, &path)?;
                match resolved {
                    ResolvedPath::Virtual { .. } => 0,
                    ResolvedPath::Host { host, .. } if host.exists() => 0,
                    ResolvedPath::Host { .. } => return Err(Errno::NoEnt.into()),
                }
            }
            SyscallNumber::Readlink => {
                let path = read_c_string(context.memory, args[0])?;
                let target = match process.resolve_path(None, &path)? {
                    ResolvedPath::Virtual {
                        file: VirtualFile::ProcSelfExe,
                        ..
                    } => process.executable_path.as_bytes().to_vec(),
                    ResolvedPath::Virtual { .. } => return Err(Errno::Inval.into()),
                    ResolvedPath::Host { host, .. } => fs::read_link(host)
                        .map_err(map_io_errno)?
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec(),
                };
                let len = target.len().min(usize_arg(args[2])?);
                context.memory.write_bytes(args[1], &target[..len])?;
                len as i64
            }
            SyscallNumber::Ioctl => {
                process.ioctl(context.memory, fd_arg(args[0])?, args[1], args[2])?
            }
            SyscallNumber::ClockGettime => {
                write_timespec(context.memory, args[1], clock_now(args[0])?)?;
                0
            }
            SyscallNumber::Nanosleep => {
                let sleep = read_timespec(context.memory, args[0])?;
                if args[1] != 0 {
                    context.memory.write_u64(args[1], 0)?;
                    context.memory.write_u64(args[1] + 8, 0)?;
                }
                thread::sleep(
                    Duration::from_secs(sleep.0)
                        .saturating_add(Duration::from_nanos(sleep.1.min(999_999_999))),
                );
                0
            }
            SyscallNumber::Times => {
                if args[0] != 0 {
                    for offset in [0, 8, 16, 24] {
                        context.memory.write_u64(args[0] + offset, 0)?;
                    }
                }
                0
            }
            SyscallNumber::Sysinfo => {
                write_sysinfo(context.memory, args[0])?;
                0
            }
            SyscallNumber::Poll | SyscallNumber::Ppoll => {
                poll_fds(process, context.memory, args[0], usize_arg(args[1])?)?
            }
            SyscallNumber::Select | SyscallNumber::Pselect6 => 0,
            SyscallNumber::Wait4 => {
                let requested = wait_requested_pid(args[0]);
                let nohang = args[2] & 0x1 != 0;
                if let Some(table) = process_table.as_deref_mut() {
                    if let Some((pid, status)) = table.wait4(ProcessId(process.pid), requested) {
                        if args[1] != 0 {
                            context.memory.write_u32(args[1], status.wait_status())?;
                        }
                        pid.0 as i64
                    } else if table.has_child(ProcessId(process.pid), requested) {
                        if nohang {
                            0
                        } else {
                            return Ok(SyscallOutcome::Blocked);
                        }
                    } else {
                        return Err(Errno::Child.into());
                    }
                } else {
                    if args[1] != 0 {
                        context.memory.write_u32(args[1], 0)?;
                    }
                    0
                }
            }
            SyscallNumber::Kill => 0,
            SyscallNumber::Clone | SyscallNumber::Fork | SyscallNumber::VFork => {
                if let (Some(table), Some(registers)) = (process_table.as_deref_mut(), registers) {
                    let pid = table.fork_from_process(process, context.memory, registers)?;
                    pid.0 as i64
                } else {
                    let pid = process.next_child_pid;
                    process.next_child_pid += 1;
                    i64::from(pid)
                }
            }
            SyscallNumber::Execve => {
                let guest_path = read_c_string(context.memory, args[0])?;
                let request =
                    process.execve_request(context.memory, &guest_path, args[1], args[2])?;
                return Ok(SyscallOutcome::Execve(request));
            }
            SyscallNumber::RtSigaction
            | SyscallNumber::RtSigprocmask
            | SyscallNumber::RtSigreturn
            | SyscallNumber::Sigaltstack
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
    entries: HashMap<i32, FdSlot>,
    next_fd: i32,
}

impl FdTable {
    pub fn new() -> Self {
        let mut entries = HashMap::new();
        entries.insert(0, FdSlot::new(FdEntry::Stdin));
        entries.insert(1, FdSlot::new(FdEntry::Stdout));
        entries.insert(2, FdSlot::new(FdEntry::Stderr));
        Self {
            entries,
            next_fd: 3,
        }
    }

    pub fn insert(&mut self, entry: FdEntry) -> i32 {
        self.insert_slot(FdSlot::new(entry))
    }

    fn insert_slot(&mut self, slot: FdSlot) -> i32 {
        let fd = self.next_available_from(self.next_fd);
        self.next_fd += 1;
        self.entries.insert(fd, slot);
        fd
    }

    pub fn set(&mut self, fd: i32, entry: FdEntry) {
        self.next_fd = self.next_fd.max(fd + 1);
        self.entries.insert(fd, FdSlot::new(entry));
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

    pub fn duplicate(
        &mut self,
        old_fd: i32,
        min_fd: i32,
        close_on_exec: bool,
    ) -> Result<i32, SyscallError> {
        let slot = self.entries.get(&old_fd).ok_or(Errno::Badf)?.duplicate()?;
        let new_fd = self.next_available_from(min_fd);
        self.set_slot(new_fd, slot.with_close_on_exec(close_on_exec));
        Ok(new_fd)
    }

    pub fn duplicate_to(
        &mut self,
        old_fd: i32,
        new_fd: i32,
        close_on_exec: bool,
    ) -> Result<i32, SyscallError> {
        if old_fd == new_fd {
            if close_on_exec {
                self.entries
                    .get_mut(&new_fd)
                    .ok_or(Errno::Badf)?
                    .close_on_exec = true;
            } else {
                self.entries.get(&old_fd).ok_or(Errno::Badf)?;
            }
            return Ok(new_fd);
        }
        let slot = self.entries.get(&old_fd).ok_or(Errno::Badf)?.duplicate()?;
        self.entries.remove(&new_fd);
        self.set_slot(new_fd, slot.with_close_on_exec(close_on_exec));
        Ok(new_fd)
    }

    pub fn pipe(&mut self, close_on_exec: bool) -> (i32, i32) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let read_fd = self.insert_slot(
            FdSlot::new(FdEntry::PipeRead(buffer.clone())).with_close_on_exec(close_on_exec),
        );
        let write_fd = self
            .insert_slot(FdSlot::new(FdEntry::PipeWrite(buffer)).with_close_on_exec(close_on_exec));
        (read_fd, write_fd)
    }

    pub fn fcntl(&mut self, fd: i32, cmd: u64, arg: u64) -> Result<i64, SyscallError> {
        match cmd {
            F_DUPFD => Ok(i64::from(self.duplicate(fd, fd_arg(arg)?, false)?)),
            F_DUPFD_CLOEXEC => Ok(i64::from(self.duplicate(fd, fd_arg(arg)?, true)?)),
            F_GETFD => Ok(if self.entries.get(&fd).ok_or(Errno::Badf)?.close_on_exec {
                FD_CLOEXEC as i64
            } else {
                0
            }),
            F_SETFD => {
                self.entries.get_mut(&fd).ok_or(Errno::Badf)?.close_on_exec = arg & FD_CLOEXEC != 0;
                Ok(0)
            }
            F_GETFL => Ok(self.entries.get(&fd).ok_or(Errno::Badf)?.status_flags as i64),
            F_SETFL => {
                self.entries.get_mut(&fd).ok_or(Errno::Badf)?.status_flags = arg;
                Ok(0)
            }
            _ => Err(Errno::Inval.into()),
        }
    }

    pub fn close_on_exec(&mut self) {
        self.entries
            .retain(|fd, slot| *fd <= 2 || !slot.close_on_exec);
    }

    pub fn duplicate_all(&self) -> Result<Self, SyscallError> {
        let mut entries = HashMap::new();
        for (fd, slot) in &self.entries {
            entries.insert(
                *fd,
                FdSlot {
                    entry: slot.entry.duplicate()?,
                    close_on_exec: slot.close_on_exec,
                    status_flags: slot.status_flags,
                },
            );
        }
        Ok(Self {
            entries,
            next_fd: self.next_fd,
        })
    }

    pub fn poll_events(&self, fd: i32, requested: i16) -> i16 {
        let Some(slot) = self.entries.get(&fd) else {
            return POLLNVAL;
        };
        let mut revents = 0;
        if requested & POLLIN != 0 && slot.read_ready() {
            revents |= POLLIN;
        }
        if requested & POLLOUT != 0 && slot.write_ready() {
            revents |= POLLOUT;
        }
        revents
    }

    pub fn getdents64(&mut self, fd: i32, bytes: &mut [u8]) -> Result<usize, SyscallError> {
        let slot = self.entries.get_mut(&fd).ok_or(Errno::Badf)?;
        match &mut slot.entry {
            FdEntry::Directory(directory) => directory.write_getdents64(bytes),
            _ => Err(Errno::NotDir.into()),
        }
    }

    pub fn read(&mut self, fd: i32, bytes: &mut [u8]) -> Result<usize, SyscallError> {
        let slot = self.entries.get_mut(&fd).ok_or(Errno::Badf)?;
        let nonblocking = slot.status_flags & O_NONBLOCK != 0;
        match &mut slot.entry {
            FdEntry::Stdin => {
                if nonblocking && !ruxeon_host::stdin_ready(Duration::ZERO).map_err(map_io_errno)? {
                    return Err(Errno::Again.into());
                }
                io::stdin().read(bytes).map_err(map_io_errno)
            }
            FdEntry::File(file) => file.read(bytes).map_err(map_io_errno),
            FdEntry::Virtual(file) => Ok(file.read(bytes)),
            FdEntry::PipeRead(buffer) => {
                let mut buffer = buffer.lock().map_err(|_| Errno::Io)?;
                let count = bytes.len().min(buffer.len());
                bytes[..count].copy_from_slice(&buffer[..count]);
                buffer.drain(..count);
                Ok(count)
            }
            FdEntry::Buffer(buffer) => {
                let mut buffer = buffer.lock().map_err(|_| Errno::Io)?;
                let count = bytes.len().min(buffer.len());
                bytes[..count].copy_from_slice(&buffer[..count]);
                buffer.drain(..count);
                Ok(count)
            }
            FdEntry::Stdout | FdEntry::Stderr | FdEntry::PipeWrite(_) | FdEntry::Directory(_) => {
                Err(Errno::Badf.into())
            }
        }
    }

    pub fn write(&mut self, fd: i32, bytes: &[u8]) -> Result<usize, SyscallError> {
        let slot = self.entries.get_mut(&fd).ok_or(Errno::Badf)?;
        match &mut slot.entry {
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
            FdEntry::Virtual(file) => Ok(file.write(bytes)),
            FdEntry::PipeWrite(buffer) => {
                buffer
                    .lock()
                    .map_err(|_| Errno::Io)?
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            FdEntry::Buffer(buffer) => {
                buffer
                    .lock()
                    .map_err(|_| Errno::Io)?
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            FdEntry::Stdin | FdEntry::PipeRead(_) | FdEntry::Directory(_) => {
                Err(Errno::Badf.into())
            }
        }
    }

    pub fn stat(&self, fd: i32) -> Result<StatData, SyscallError> {
        let slot = self.entries.get(&fd).ok_or(Errno::Badf)?;
        match &slot.entry {
            FdEntry::File(file) => stat_from_metadata(file.metadata().map_err(map_io_errno)?),
            FdEntry::Directory(directory) => write_stat_data_for_path(&directory.path),
            FdEntry::Virtual(file) => Ok(file.stat()),
            FdEntry::Stdin
            | FdEntry::Stdout
            | FdEntry::Stderr
            | FdEntry::PipeRead(_)
            | FdEntry::PipeWrite(_)
            | FdEntry::Buffer(_) => Ok(StatData::char_device()),
        }
    }

    fn set_slot(&mut self, fd: i32, slot: FdSlot) {
        self.next_fd = self.next_fd.max(fd + 1);
        self.entries.insert(fd, slot);
    }

    fn next_available_from(&self, min_fd: i32) -> i32 {
        let mut fd = min_fd.max(0);
        while self.entries.contains_key(&fd) {
            fd += 1;
        }
        fd
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
    Directory(DirectoryFd),
    Virtual(VirtualFd),
    PipeRead(Arc<Mutex<Vec<u8>>>),
    PipeWrite(Arc<Mutex<Vec<u8>>>),
    Buffer(Arc<Mutex<Vec<u8>>>),
}

#[derive(Debug)]
struct FdSlot {
    entry: FdEntry,
    close_on_exec: bool,
    status_flags: u64,
}

impl FdSlot {
    fn new(entry: FdEntry) -> Self {
        Self {
            entry,
            close_on_exec: false,
            status_flags: 0,
        }
    }

    fn with_close_on_exec(mut self, close_on_exec: bool) -> Self {
        self.close_on_exec = close_on_exec;
        self
    }

    fn duplicate(&self) -> Result<Self, SyscallError> {
        Ok(Self {
            entry: self.entry.duplicate()?,
            close_on_exec: false,
            status_flags: self.status_flags,
        })
    }

    fn read_ready(&self) -> bool {
        match &self.entry {
            FdEntry::Stdin if self.status_flags & O_NONBLOCK != 0 => {
                ruxeon_host::stdin_ready(Duration::ZERO).unwrap_or(false)
            }
            FdEntry::Stdin | FdEntry::File(_) | FdEntry::Virtual(_) | FdEntry::Directory(_) => true,
            FdEntry::PipeRead(buffer) | FdEntry::Buffer(buffer) => buffer
                .lock()
                .map(|buffer| !buffer.is_empty())
                .unwrap_or(false),
            FdEntry::Stdout | FdEntry::Stderr | FdEntry::PipeWrite(_) => false,
        }
    }

    fn write_ready(&self) -> bool {
        matches!(
            &self.entry,
            FdEntry::Stdout
                | FdEntry::Stderr
                | FdEntry::File(_)
                | FdEntry::Virtual(_)
                | FdEntry::PipeWrite(_)
                | FdEntry::Buffer(_)
        )
    }
}

impl FdEntry {
    fn duplicate(&self) -> Result<Self, SyscallError> {
        match self {
            Self::Stdin => Ok(Self::Stdin),
            Self::Stdout => Ok(Self::Stdout),
            Self::Stderr => Ok(Self::Stderr),
            Self::File(file) => Ok(Self::File(file.try_clone().map_err(map_io_errno)?)),
            Self::Directory(directory) => Ok(Self::Directory(directory.clone())),
            Self::Virtual(file) => Ok(Self::Virtual(file.clone())),
            Self::PipeRead(buffer) => Ok(Self::PipeRead(buffer.clone())),
            Self::PipeWrite(buffer) => Ok(Self::PipeWrite(buffer.clone())),
            Self::Buffer(buffer) => Ok(Self::Buffer(buffer.clone())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirectoryFd {
    path: PathBuf,
    entries: Vec<DirectoryEntry>,
    cursor: usize,
}

impl DirectoryFd {
    fn open(path: PathBuf) -> Result<Self, SyscallError> {
        let mut entries = vec![
            DirectoryEntry {
                name: ".".to_string(),
                kind: 4,
            },
            DirectoryEntry {
                name: "..".to_string(),
                kind: 4,
            },
        ];
        for entry in fs::read_dir(&path).map_err(map_io_errno)? {
            let entry = entry.map_err(map_io_errno)?;
            let kind = entry.file_type().map_err(map_io_errno)?;
            entries.push(DirectoryEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                kind: if kind.is_dir() { 4 } else { 8 },
            });
        }
        Ok(Self {
            path,
            entries,
            cursor: 0,
        })
    }

    fn write_getdents64(&mut self, output: &mut [u8]) -> Result<usize, SyscallError> {
        let mut written = 0;
        while self.cursor < self.entries.len() {
            let entry = &self.entries[self.cursor];
            let name = entry.name.as_bytes();
            let reclen = align_usize(19 + name.len() + 1, 8);
            if written + reclen > output.len() {
                break;
            }
            let ino = (self.cursor + 1) as u64;
            let offset = (self.cursor + 1) as i64;
            output[written..written + 8].copy_from_slice(&ino.to_le_bytes());
            output[written + 8..written + 16].copy_from_slice(&offset.to_le_bytes());
            output[written + 16..written + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
            output[written + 18] = entry.kind;
            output[written + 19..written + 19 + name.len()].copy_from_slice(name);
            output[written + 19 + name.len()] = 0;
            for byte in &mut output[written + 19 + name.len() + 1..written + reclen] {
                *byte = 0;
            }
            written += reclen;
            self.cursor += 1;
        }
        Ok(written)
    }
}

#[derive(Debug, Clone)]
struct DirectoryEntry {
    name: String,
    kind: u8,
}

#[derive(Debug, Clone)]
pub struct VirtualFd {
    file: VirtualFile,
    data: Vec<u8>,
    cursor: usize,
}

impl VirtualFd {
    fn new(file: VirtualFile, executable_path: &str) -> Self {
        let data = match file {
            VirtualFile::DevNull
            | VirtualFile::DevZero
            | VirtualFile::DevRandom
            | VirtualFile::DevURandom => Vec::new(),
            _ => file.read_bytes(executable_path, usize::MAX),
        };
        Self {
            file,
            data,
            cursor: 0,
        }
    }

    fn read(&mut self, bytes: &mut [u8]) -> usize {
        match self.file {
            VirtualFile::DevNull => 0,
            VirtualFile::DevZero | VirtualFile::DevRandom | VirtualFile::DevURandom => {
                let data = self.file.read_bytes("", bytes.len());
                bytes[..data.len()].copy_from_slice(&data);
                data.len()
            }
            _ => {
                let remaining = self.data.len().saturating_sub(self.cursor);
                let count = bytes.len().min(remaining);
                bytes[..count].copy_from_slice(&self.data[self.cursor..self.cursor + count]);
                self.cursor += count;
                count
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) -> usize {
        self.file.write(bytes)
    }

    fn stat(&self) -> StatData {
        match self.file {
            VirtualFile::DevNull
            | VirtualFile::DevZero
            | VirtualFile::DevRandom
            | VirtualFile::DevURandom => StatData::char_device(),
            _ => StatData::regular(self.data.len() as u64),
        }
    }
}

impl LinuxProcess {
    fn mkdir_guest_path(&mut self, dirfd: Option<i32>, path: &str) -> Result<u32, SyscallError> {
        match self.resolve_path(dirfd, path)? {
            ResolvedPath::Virtual { .. } => Err(Errno::Acces.into()),
            ResolvedPath::Host { host, .. } => {
                fs::create_dir(&host).map_err(map_io_errno)?;
                Ok(0)
            }
        }
    }

    fn remove_guest_path(
        &mut self,
        dirfd: Option<i32>,
        path: &str,
        remove_dir: bool,
    ) -> Result<u32, SyscallError> {
        match self.resolve_path(dirfd, path)? {
            ResolvedPath::Virtual { .. } => Err(Errno::Acces.into()),
            ResolvedPath::Host { host, .. } => {
                if remove_dir {
                    fs::remove_dir(&host).map_err(map_io_errno)?;
                } else {
                    fs::remove_file(&host).map_err(map_io_errno)?;
                }
                Ok(0)
            }
        }
    }

    fn open_guest_path(
        &mut self,
        dirfd: Option<i32>,
        path: &str,
        flags: u64,
    ) -> Result<i32, SyscallError> {
        let resolved = self.resolve_path(dirfd, path)?;
        if let ResolvedPath::Virtual { file, .. } = resolved {
            return Ok(self.fd_table.insert(FdEntry::Virtual(VirtualFd::new(
                file,
                &self.executable_path,
            ))));
        }
        let ResolvedPath::Host {
            host: host_path, ..
        } = resolved
        else {
            unreachable!("virtual path handled above");
        };
        if flags & O_DIRECTORY != 0 {
            if !host_path.is_dir() {
                return Err(Errno::NotDir.into());
            }
            return Ok(self
                .fd_table
                .insert(FdEntry::Directory(DirectoryFd::open(host_path)?)));
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

    fn write_stat_for_guest_path(
        &self,
        memory: &mut GuestMemory,
        dirfd: Option<i32>,
        path: &str,
        addr: u64,
    ) -> Result<(), SyscallError> {
        match self.resolve_path(dirfd, path)? {
            ResolvedPath::Virtual { file, .. } => write_stat(
                memory,
                addr,
                VirtualFd::new(file, &self.executable_path).stat(),
            ),
            ResolvedPath::Host { host, .. } => write_stat_for_path(memory, addr, &host),
        }
    }

    fn resolve_path(&self, dirfd: Option<i32>, path: &str) -> Result<ResolvedPath, SyscallError> {
        if path.is_empty() {
            return Err(Errno::NoEnt.into());
        }
        if let Some(rootfs) = &self.rootfs {
            if path.starts_with('/') || dirfd.is_none() {
                return rootfs.resolve(&self.cwd, path).map_err(SyscallError::from);
            }
        }
        if path.starts_with('/') || dirfd.is_none() {
            let guest = self.normalize_guest_path(path)?;
            if let Some(file) = VirtualFile::from_guest_path(guest.as_str()) {
                return Ok(ResolvedPath::Virtual { guest, file });
            }
            return Ok(ResolvedPath::Host {
                host: PathBuf::from(guest.as_str()),
                guest,
            });
        }
        let fd = dirfd.expect("checked above");
        match self.fd_table.entries.get(&fd) {
            Some(slot) => match &slot.entry {
                FdEntry::Directory(directory) => Ok(ResolvedPath::Host {
                    guest: GuestPath::parse(path).map_err(SyscallError::from)?,
                    host: directory.path.join(path.replace('/', "\\")),
                }),
                _ => Err(Errno::Badf.into()),
            },
            _ => Err(Errno::Badf.into()),
        }
    }

    fn normalize_guest_path(&self, path: &str) -> Result<GuestPath, SyscallError> {
        self.cwd.join(path).map_err(SyscallError::from)
    }

    fn execve_request(
        &self,
        memory: &GuestMemory,
        guest_path: &str,
        argv_addr: u64,
        envp_addr: u64,
    ) -> Result<ExecveRequest, SyscallError> {
        let resolved = self.resolve_path(None, guest_path)?;
        let host_path = match resolved {
            ResolvedPath::Host { host, .. } => host,
            ResolvedPath::Virtual { .. } => return Err(Errno::Acces.into()),
        };
        Ok(ExecveRequest {
            guest_path: guest_path.to_string(),
            host_path,
            rootfs: self
                .rootfs
                .as_ref()
                .map(|rootfs| rootfs.host_root().to_path_buf()),
            argv: read_string_vector(memory, argv_addr)?,
            envp: read_string_vector(memory, envp_addr)?,
        })
    }

    fn ioctl(
        &mut self,
        memory: &mut GuestMemory,
        fd: i32,
        request: u64,
        arg: u64,
    ) -> Result<i64, SyscallError> {
        match request {
            TIOCGWINSZ => {
                self.require_terminal_fd(fd)?;
                if arg != 0 {
                    self.terminal.write_winsize(memory, arg)?;
                }
                Ok(0)
            }
            TIOCSWINSZ => {
                self.require_terminal_fd(fd)?;
                if arg != 0 {
                    self.terminal.read_winsize(memory, arg)?;
                }
                Ok(0)
            }
            TCGETS => {
                self.require_terminal_fd(fd)?;
                if arg != 0 {
                    self.terminal.write_termios(memory, arg)?;
                }
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                self.require_terminal_fd(fd)?;
                if arg != 0 {
                    self.terminal.read_termios(memory, arg)?;
                    self.terminal.apply_host_mode()?;
                }
                Ok(0)
            }
            TIOCGPGRP => {
                self.require_terminal_fd(fd)?;
                if arg != 0 {
                    memory.write_u32(arg, self.pgid)?;
                }
                Ok(0)
            }
            TIOCSPGRP => {
                self.require_terminal_fd(fd)?;
                Ok(0)
            }
            _ => Err(Errno::Inval.into()),
        }
    }

    fn require_terminal_fd(&self, fd: i32) -> Result<(), SyscallError> {
        let slot = self.fd_table.entries.get(&fd).ok_or(Errno::Badf)?;
        if matches!(
            &slot.entry,
            FdEntry::Stdin | FdEntry::Stdout | FdEntry::Stderr
        ) {
            Ok(())
        } else {
            Err(Errno::NoTty.into())
        }
    }
}

impl From<FsError> for SyscallError {
    fn from(value: FsError) -> Self {
        match value {
            FsError::EmptyPath => Errno::NoEnt.into(),
            FsError::WindowsPrefix | FsError::NulByte => Errno::Inval.into(),
            FsError::TooManySymlinks => Errno::Loop.into(),
        }
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

fn read_string_vector(memory: &GuestMemory, addr: u64) -> Result<Vec<String>, SyscallError> {
    if addr == 0 {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for index in 0..4096u64 {
        let ptr = memory.read_u64(addr + index * 8)?;
        if ptr == 0 {
            return Ok(values);
        }
        values.push(read_c_string(memory, ptr)?);
    }
    Err(Errno::Inval.into())
}

fn read_timespec(memory: &GuestMemory, addr: u64) -> Result<(u64, u64), SyscallError> {
    if addr == 0 {
        return Err(Errno::Fault.into());
    }
    Ok((memory.read_u64(addr)?, memory.read_u64(addr + 8)?))
}

fn write_timespec(
    memory: &mut GuestMemory,
    addr: u64,
    value: (u64, u64),
) -> Result<(), SyscallError> {
    if addr == 0 {
        return Err(Errno::Fault.into());
    }
    memory.write_u64(addr, value.0)?;
    memory.write_u64(addr + 8, value.1)?;
    Ok(())
}

fn clock_now(clock: u64) -> Result<(u64, u64), SyscallError> {
    match clock {
        CLOCK_REALTIME | CLOCK_MONOTONIC => {
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Errno::Inval)?;
            Ok((duration.as_secs(), u64::from(duration.subsec_nanos())))
        }
        _ => Err(Errno::Inval.into()),
    }
}

fn write_sysinfo(memory: &mut GuestMemory, addr: u64) -> Result<(), SyscallError> {
    if addr == 0 {
        return Err(Errno::Fault.into());
    }
    let mut bytes = vec![0; 112];
    write_u64(&mut bytes, 0, 0);
    write_u64(&mut bytes, 8, 0);
    write_u64(&mut bytes, 16, 0);
    write_u64(&mut bytes, 24, 0);
    write_u64(&mut bytes, 32, 1024 * 1024 * 1024);
    write_u64(&mut bytes, 40, 512 * 1024 * 1024);
    write_u64(&mut bytes, 48, 0);
    write_u64(&mut bytes, 56, 0);
    write_u64(&mut bytes, 64, 0);
    write_u16(&mut bytes, 72, 1);
    write_u32(&mut bytes, 80, 4096);
    memory.write_bytes(addr, &bytes)?;
    Ok(())
}

fn poll_fds(
    process: &mut LinuxProcess,
    memory: &mut GuestMemory,
    addr: u64,
    count: usize,
) -> Result<i64, SyscallError> {
    let mut ready = 0;
    for index in 0..count {
        let base = addr + (index as u64) * 8;
        let fd = memory.read_u32(base)? as i32;
        let events = memory.read_u16(base + 4)? as i16;
        let revents = process.fd_table.poll_events(fd, events);
        memory.write_u16(base + 6, revents as u16)?;
        if revents != 0 {
            ready += 1;
        }
    }
    Ok(ready)
}

fn writev(
    process: &mut LinuxProcess,
    memory: &GuestMemory,
    fd: i32,
    iov_addr: u64,
    iov_count: usize,
) -> Result<i64, SyscallError> {
    let mut total = 0usize;
    for index in 0..iov_count {
        let entry = iov_addr + (index as u64 * 16);
        let base = memory.read_u64(entry)?;
        let len = usize_arg(memory.read_u64(entry + 8)?)?;
        if len == 0 {
            continue;
        }
        let bytes = memory.read_bytes(base, len)?;
        total += process.fd_table.write(fd, &bytes)?;
    }
    Ok(total as i64)
}

fn readv(
    process: &mut LinuxProcess,
    memory: &mut GuestMemory,
    fd: i32,
    iov_addr: u64,
    iov_count: usize,
) -> Result<i64, SyscallError> {
    let mut total = 0usize;
    for index in 0..iov_count {
        let entry = iov_addr + (index as u64 * 16);
        let base = memory.read_u64(entry)?;
        let len = usize_arg(memory.read_u64(entry + 8)?)?;
        if len == 0 {
            continue;
        }
        let mut bytes = vec![0; len];
        let count = process.fd_table.read(fd, &mut bytes)?;
        memory.write_bytes(base, &bytes[..count])?;
        total += count;
        if count < len {
            break;
        }
    }
    Ok(total as i64)
}

fn sendfile(
    process: &mut LinuxProcess,
    memory: &mut GuestMemory,
    out_fd: i32,
    in_fd: i32,
    offset_addr: u64,
    count: usize,
) -> Result<i64, SyscallError> {
    const CHUNK_SIZE: usize = 8192;

    if count == 0 {
        return Ok(0);
    }

    let mut requested_offset = if offset_addr == 0 {
        None
    } else {
        Some(memory.read_u64(offset_addr)?)
    };

    let mut total = 0usize;
    while total < count {
        let chunk_len = (count - total).min(CHUNK_SIZE);
        let mut chunk = vec![0; chunk_len];
        let read = read_sendfile_chunk(process, in_fd, &mut requested_offset, &mut chunk)?;
        if read == 0 {
            break;
        }

        let mut written = 0usize;
        while written < read {
            let count = process.fd_table.write(out_fd, &chunk[written..read])?;
            if count == 0 {
                return Err(Errno::Io.into());
            }
            written += count;
        }
        total += read;
    }

    if let Some(offset) = requested_offset {
        memory.write_u64(offset_addr, offset)?;
    }

    Ok(total as i64)
}

fn read_sendfile_chunk(
    process: &mut LinuxProcess,
    fd: i32,
    offset: &mut Option<u64>,
    chunk: &mut [u8],
) -> Result<usize, SyscallError> {
    let slot = process.fd_table.entries.get_mut(&fd).ok_or(Errno::Badf)?;
    match &mut slot.entry {
        FdEntry::File(file) => {
            let saved_position = if let Some(offset) = *offset {
                let current = file.stream_position().map_err(map_io_errno)?;
                file.seek(SeekFrom::Start(offset)).map_err(map_io_errno)?;
                Some(current)
            } else {
                None
            };

            let read = file.read(chunk).map_err(map_io_errno)?;

            if let Some(offset_value) = offset.as_mut() {
                *offset_value = offset_value.saturating_add(read as u64);
            }
            if let Some(position) = saved_position {
                file.seek(SeekFrom::Start(position)).map_err(map_io_errno)?;
            }
            Ok(read)
        }
        FdEntry::Virtual(file) => {
            let saved_cursor = if let Some(offset) = *offset {
                let current = file.cursor;
                file.cursor = offset as usize;
                Some(current)
            } else {
                None
            };

            let read = file.read(chunk);
            if let Some(offset_value) = offset.as_mut() {
                *offset_value = offset_value.saturating_add(read as u64);
            }
            if let Some(cursor) = saved_cursor {
                file.cursor = cursor;
            }
            Ok(read)
        }
        FdEntry::Directory(_) => Err(Errno::IsDir.into()),
        FdEntry::Stdin
        | FdEntry::Stdout
        | FdEntry::Stderr
        | FdEntry::PipeRead(_)
        | FdEntry::PipeWrite(_)
        | FdEntry::Buffer(_) => Err(Errno::Inval.into()),
    }
}

fn wait_requested_pid(raw: u64) -> Option<ProcessId> {
    let value = raw as i64;
    if value <= 0 {
        None
    } else {
        Some(ProcessId(value as u32))
    }
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
        io::ErrorKind::AlreadyExists => Errno::Exist.into(),
        io::ErrorKind::InvalidInput => Errno::Inval.into(),
        io::ErrorKind::WouldBlock => Errno::Again.into(),
        _ => Errno::Io.into(),
    }
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
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

fn align_usize(value: usize, align: usize) -> usize {
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

    #[test]
    fn opens_and_reads_virtual_proc_file() {
        let mut process = LinuxProcess::new(None);
        let mut memory = memory_with_data(0x1000, b"/proc/cpuinfo\0");

        let opened = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Open.raw(),
                args: [0x1000, 0, 0, 0, 0, 0],
            },
        );
        let SyscallOutcome::Return(fd) = opened else {
            panic!("expected fd");
        };
        assert!(fd >= 3);

        let read = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Read.raw(),
                args: [fd as u64, 0x1100, 64, 0, 0, 0],
            },
        );
        let SyscallOutcome::Return(count) = read else {
            panic!("expected read count");
        };
        assert!(count > 0);
        let bytes = memory.read_bytes(0x1100, count as usize).unwrap();
        assert!(String::from_utf8(bytes).unwrap().contains("processor"));
    }

    #[test]
    fn terminal_ioctls_round_trip_termios_and_winsize() {
        let mut process = LinuxProcess::new(None);
        let mut memory = memory_with_data(0x1000, &[0; 0x1000]);

        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Ioctl.raw(),
                    args: [0, TCGETS, 0x1000, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(0)
        );
        let lflag = memory.read_u32(0x1000 + 12).unwrap();
        assert_ne!(lflag & ICANON, 0);
        assert_ne!(lflag & ECHO, 0);

        let mut termios = memory.read_bytes(0x1000, TERMIOS_SIZE).unwrap();
        termios[12..16].copy_from_slice(&(lflag & !ECHO).to_le_bytes());
        memory.write_bytes(0x1100, &termios).unwrap();
        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Ioctl.raw(),
                    args: [0, TCSETS, 0x1100, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Ioctl.raw(),
                    args: [0, TCGETS, 0x1200, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(0)
        );
        let updated_lflag = memory.read_u32(0x1200 + 12).unwrap();
        assert_eq!(updated_lflag & ECHO, 0);
        assert_ne!(updated_lflag & ICANON, 0);

        memory.write_u16(0x1300, 40).unwrap();
        memory.write_u16(0x1302, 120).unwrap();
        memory.write_u16(0x1304, 1).unwrap();
        memory.write_u16(0x1306, 2).unwrap();
        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Ioctl.raw(),
                    args: [1, TIOCSWINSZ, 0x1300, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Ioctl.raw(),
                    args: [1, TIOCGWINSZ, 0x1400, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(memory.read_u16(0x1400).unwrap(), 40);
        assert_eq!(memory.read_u16(0x1402).unwrap(), 120);
    }

    #[test]
    fn terminal_ioctl_rejects_non_terminal_fds() {
        let mut process = LinuxProcess::new(None);
        process
            .fd_table_mut()
            .install_buffer(3, Arc::new(Mutex::new(Vec::new())));
        let mut memory = memory_with_data(0x1000, &[0; 128]);

        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Ioctl.raw(),
                    args: [3, TCGETS, 0x1000, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(Errno::NoTty.linux_return())
        );
    }

    #[test]
    fn terminal_ioctl_accepts_duplicated_stdio_fds() {
        let mut process = LinuxProcess::new(None);
        let dup_fd = process.fd_table_mut().duplicate(0, 3, false).unwrap();
        let mut memory = memory_with_data(0x1000, &[0; 128]);

        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Ioctl.raw(),
                    args: [dup_fd as u64, TCGETS, 0x1000, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(0)
        );
    }

    #[test]
    fn pipe_dup_and_poll_round_trip_data() {
        let mut process = LinuxProcess::new(None);
        let mut memory = memory_with_data(0x1000, &[0; 128]);
        memory.write_bytes(0x1080, b"abc").unwrap();

        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Pipe.raw(),
                    args: [0x1000, 0, 0, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(0)
        );
        let read_fd = memory.read_u32(0x1000).unwrap();
        let write_fd = memory.read_u32(0x1004).unwrap();

        let dup_fd = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Dup.raw(),
                args: [write_fd as u64, 0, 0, 0, 0, 0],
            },
        );
        let SyscallOutcome::Return(dup_fd) = dup_fd else {
            panic!("expected dup fd");
        };

        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Write.raw(),
                    args: [dup_fd as u64, 0x1080, 3, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(3)
        );

        memory.write_u32(0x1100, read_fd).unwrap();
        memory.write_u16(0x1104, POLLIN as u16).unwrap();
        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Poll.raw(),
                    args: [0x1100, 1, 0, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(1)
        );

        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::Read.raw(),
                    args: [read_fd as u64, 0x1200, 3, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(3)
        );
        assert_eq!(memory.read_bytes(0x1200, 3).unwrap(), b"abc");
    }

    #[test]
    fn getdents64_returns_directory_entries() {
        let root = std::env::temp_dir().join(format!("ruxeon-getdents-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("file.txt"), b"x").unwrap();

        let mut process = LinuxProcess::new(Some(root.clone()));
        let mut memory = memory_with_data(0x1000, b"/\0");
        let opened = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Open.raw(),
                args: [0x1000, O_DIRECTORY, 0, 0, 0, 0],
            },
        );
        let SyscallOutcome::Return(fd) = opened else {
            panic!("expected directory fd");
        };
        let read = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Getdents64.raw(),
                args: [fd as u64, 0x1100, 512, 0, 0, 0],
            },
        );
        let SyscallOutcome::Return(count) = read else {
            panic!("expected byte count");
        };
        assert!(count > 0);
        let bytes = memory.read_bytes(0x1100, count as usize).unwrap();
        assert!(bytes
            .windows("file.txt".len())
            .any(|window| window == b"file.txt"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn clock_gettime_writes_timespec() {
        let mut process = LinuxProcess::new(None);
        let mut memory = memory_with_data(0x1000, &[0; 32]);

        assert_eq!(
            SyscallDispatcher::dispatch(
                &mut process,
                &mut SyscallContext {
                    memory: &mut memory
                },
                SyscallInput {
                    number: SyscallNumber::ClockGettime.raw(),
                    args: [CLOCK_REALTIME, 0x1000, 0, 0, 0, 0],
                },
            ),
            SyscallOutcome::Return(0)
        );
        assert!(memory.read_u64(0x1000).unwrap() > 0);
    }

    #[test]
    fn execve_returns_load_request() {
        let root = std::env::temp_dir().join(format!("ruxeon-execve-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/sh"), b"fake").unwrap();

        let mut process = LinuxProcess::new(Some(root.clone()));
        let mut memory = memory_with_data(0x1000, &[0; 512]);
        memory.write_bytes(0x1000, b"/bin/sh\0").unwrap();
        memory.write_u64(0x1100, 0x1000).unwrap();
        memory.write_u64(0x1108, 0).unwrap();
        memory.write_u64(0x1200, 0).unwrap();

        let outcome = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Execve.raw(),
                args: [0x1000, 0x1100, 0x1200, 0, 0, 0],
            },
        );
        let SyscallOutcome::Execve(request) = outcome else {
            panic!("expected execve request");
        };
        assert_eq!(request.guest_path, "/bin/sh");
        assert_eq!(request.argv, vec!["/bin/sh"]);
        assert_eq!(request.host_path, root.join("bin/sh"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn process_table_forks_snapshots_and_waits_for_exit() {
        let parent = LinuxProcess::new(None);
        let memory = memory_with_data(0x1000, b"parent");
        let registers = Registers {
            rip: 0x4000,
            rax: 123,
            ..Registers::default()
        };
        let mut table = ProcessTable::new();
        let parent_pid = table.insert_initial(LinuxProcess::new(None), memory.clone(), registers);

        let child_pid = table
            .fork_from_process(&parent, &memory, registers)
            .unwrap();

        let child = table.get(child_pid).unwrap();
        assert_eq!(child.parent, Some(parent_pid));
        assert_eq!(child.memory.read_bytes(0x1000, 6).unwrap(), b"parent");
        let child_thread = child.threads.values().next().unwrap();
        assert_eq!(child_thread.registers.rax, 0);

        table.exit_process(child_pid, 7);
        let waited = table.wait4(parent_pid, Some(child_pid)).unwrap();
        assert_eq!(waited.0, child_pid);
        assert_eq!(waited.1.wait_status(), 7 << 8);
    }

    #[test]
    fn scheduler_round_robins_runnable_threads() {
        let process = LinuxProcess::new(None);
        let memory = GuestMemory::new();
        let mut table = ProcessTable::new();
        let pid = table.insert_initial(process, memory, Registers::default());
        let mut scheduler = Scheduler::new();
        scheduler.enqueue_process(table.get(pid).unwrap());

        assert_eq!(scheduler.next_thread(&table).unwrap().0, pid);
        table.exit_process(pid, 0);
        assert_eq!(scheduler.next_thread(&table), None);
    }

    #[test]
    fn dispatch_fork_and_wait_use_process_table() {
        let mut process = LinuxProcess::new(None);
        let mut memory = memory_with_data(0x1000, &[0; 16]);
        let registers = Registers {
            rip: 0x401000,
            rsp: 0x8000,
            ..Registers::default()
        };
        let mut table = ProcessTable::new();
        let parent_pid = table.insert_initial(LinuxProcess::new(None), memory.clone(), registers);
        assert_eq!(parent_pid, ProcessId(process.pid()));

        let forked = SyscallDispatcher::dispatch_with_process_model(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Fork.raw(),
                args: [0; 6],
            },
            Some(&mut table),
            Some(registers),
        );
        let SyscallOutcome::Return(child_pid) = forked else {
            panic!("expected child pid");
        };
        let child_pid = ProcessId(child_pid as u32);
        assert!(table.get(child_pid).is_some());

        table.exit_process(child_pid, 3);
        let waited = SyscallDispatcher::dispatch_with_process_model(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Wait4.raw(),
                args: [child_pid.0 as u64, 0x1000, 0, 0, 0, 0],
            },
            Some(&mut table),
            Some(registers),
        );

        assert_eq!(waited, SyscallOutcome::Return(child_pid.0 as i64));
        assert_eq!(memory.read_u32(0x1000).unwrap(), 3 << 8);
    }

    #[test]
    fn blocking_wait4_wakes_parent_when_child_exits() {
        let mut process = LinuxProcess::new(None);
        let mut memory = memory_with_data(0x1000, &[0; 16]);
        let registers = Registers {
            rip: 0x401000,
            rsp: 0x8000,
            ..Registers::default()
        };
        let mut table = ProcessTable::new();
        let parent_pid = table.insert_initial(LinuxProcess::new(None), memory.clone(), registers);
        assert_eq!(parent_pid, ProcessId(process.pid()));

        let forked = SyscallDispatcher::dispatch_with_process_model(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Fork.raw(),
                args: [0; 6],
            },
            Some(&mut table),
            Some(registers),
        );
        let SyscallOutcome::Return(child_pid) = forked else {
            panic!("expected child pid");
        };
        let child_pid = ProcessId(child_pid as u32);

        let waiting = SyscallDispatcher::dispatch_with_process_model(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Wait4.raw(),
                args: [child_pid.0 as u64, 0x1000, 0, 0, 0, 0],
            },
            Some(&mut table),
            None,
        );
        assert_eq!(waiting, SyscallOutcome::Blocked);

        let parent_record = table.get_mut(parent_pid).unwrap();
        parent_record.state = ProcessState::Waiting;
        for thread in parent_record.threads.values_mut() {
            thread.state = ProcessState::Waiting;
        }

        table.record_exit(child_pid, Some(parent_pid), 9);
        let parent_record = table.get(parent_pid).unwrap();
        assert_eq!(parent_record.state, ProcessState::Runnable);
        assert!(parent_record
            .threads
            .values()
            .all(|thread| thread.state == ProcessState::Runnable));

        let waited = SyscallDispatcher::dispatch_with_process_model(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Wait4.raw(),
                args: [child_pid.0 as u64, 0x1000, 0, 0, 0, 0],
            },
            Some(&mut table),
            None,
        );
        assert_eq!(waited, SyscallOutcome::Return(child_pid.0 as i64));
        assert_eq!(memory.read_u32(0x1000).unwrap(), 9 << 8);
    }

    #[test]
    fn mkdir_creates_directory_inside_rootfs() {
        let root = std::env::temp_dir().join(format!("ruxeon-mkdir-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let mut process = LinuxProcess::new(Some(root.clone()));
        let mut memory = memory_with_data(0x1000, b"/demo\0");
        let outcome = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Mkdir.raw(),
                args: [0x1000, 0o755, 0, 0, 0, 0],
            },
        );

        assert_eq!(outcome, SyscallOutcome::Return(0));
        assert!(root.join("demo").is_dir());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn unlink_removes_file_inside_rootfs() {
        let root = std::env::temp_dir().join(format!("ruxeon-unlink-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("demo.txt"), b"hello").unwrap();

        let mut process = LinuxProcess::new(Some(root.clone()));
        let mut memory = memory_with_data(0x1000, b"/demo.txt\0");
        let outcome = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Unlink.raw(),
                args: [0x1000, 0, 0, 0, 0, 0],
            },
        );

        assert_eq!(outcome, SyscallOutcome::Return(0));
        assert!(!root.join("demo.txt").exists());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rmdir_removes_directory_inside_rootfs() {
        let root = std::env::temp_dir().join(format!("ruxeon-rmdir-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("demo")).unwrap();

        let mut process = LinuxProcess::new(Some(root.clone()));
        let mut memory = memory_with_data(0x1000, b"/demo\0");
        let outcome = SyscallDispatcher::dispatch(
            &mut process,
            &mut SyscallContext {
                memory: &mut memory,
            },
            SyscallInput {
                number: SyscallNumber::Rmdir.raw(),
                args: [0x1000, 0, 0, 0, 0, 0],
            },
        );

        assert_eq!(outcome, SyscallOutcome::Return(0));
        assert!(!root.join("demo").exists());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn signal_state_queues_and_takes_signals() {
        let mut signals = SignalState::default();
        signals.enqueue(2);
        signals.enqueue(15);

        assert_eq!(signals.pending(), &[2, 15]);
        assert_eq!(signals.take_next(), Some(2));
        assert_eq!(signals.take_next(), Some(15));
        assert_eq!(signals.take_next(), None);
    }
}
