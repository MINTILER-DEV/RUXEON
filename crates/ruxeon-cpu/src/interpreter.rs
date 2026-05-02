use crate::Registers;
use ruxeon_core::GuestMemory;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CpuError {
    #[error("CPU interpreter is not implemented yet")]
    NotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallTrap {
    pub number: u64,
    pub args: [u64; 6],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRecord {
    pub ip: u64,
    pub instruction: String,
    pub before: Registers,
    pub after: Registers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    Continue,
    Syscall(SyscallTrap),
    Halted(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Syscall(SyscallTrap),
    Exited(i32),
    StepLimit,
}

pub struct Interpreter {
    memory: GuestMemory,
    registers: Registers,
    trace: Vec<TraceRecord>,
}

impl Interpreter {
    pub fn new(memory: GuestMemory, registers: Registers) -> Self {
        Self {
            memory,
            registers,
            trace: Vec::new(),
        }
    }

    pub fn memory(&self) -> &GuestMemory {
        &self.memory
    }

    pub fn registers(&self) -> &Registers {
        &self.registers
    }

    pub fn trace(&self) -> &[TraceRecord] {
        &self.trace
    }

    pub fn step(&mut self) -> Result<StepOutcome, CpuError> {
        Err(CpuError::NotImplemented)
    }

    pub fn run(&mut self, _max_steps: u64) -> Result<RunOutcome, CpuError> {
        Err(CpuError::NotImplemented)
    }
}
