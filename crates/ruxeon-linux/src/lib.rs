//! Linux syscall layer scaffolding for Phase 3.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Errno {
    Perm = 1,
    NoEnt = 2,
    Intr = 4,
    Io = 5,
    Badf = 9,
    Again = 11,
    NoMem = 12,
    Acces = 13,
    Fault = 14,
    Inval = 22,
    NoSys = 38,
}

impl Errno {
    pub const fn linux_return(self) -> i64 {
        -(self as i64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    Read,
    Write,
    Open,
    Close,
    Exit,
    ExitGroup,
    Other(u64),
}

impl From<u64> for SyscallNumber {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::Open,
            3 => Self::Close,
            60 => Self::Exit,
            231 => Self::ExitGroup,
            other => Self::Other(other),
        }
    }
}
