use crate::registers::{
    register_width, RegisterError, Registers, FLAG_CF, FLAG_DF, FLAG_OF, FLAG_PF, FLAG_SF, FLAG_ZF,
};
use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind,
    Register,
};
use ruxeon_core::{GuestMemory, GuestMemoryError, MemoryPermission};
use ruxeon_ir::{
    BasicBlock, BasicBlockId, BlockCache, BlockCacheStats, BlockTerminator, IrInstruction,
    IrInstructionKind,
};
use std::collections::HashMap;
use thiserror::Error;

const MAX_INSTRUCTION_LEN: usize = 15;
const MAX_BLOCK_INSTRUCTIONS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedInstructionRecord {
    pub ip: u64,
    pub raw_bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub text: String,
    pub registers: Registers,
}

#[derive(Debug, Error)]
pub enum CpuError {
    #[error(transparent)]
    Memory(#[from] GuestMemoryError),
    #[error(transparent)]
    Register(#[from] RegisterError),
    #[error("invalid instruction at {0:#x}")]
    InvalidInstruction(u64),
    #[error(
        "unsupported instruction at {ip:#x}: {text}",
        ip = record.ip,
        text = record.text
    )]
    UnsupportedInstruction {
        record: UnsupportedInstructionRecord,
    },
    #[error("unsupported operand at {ip:#x}: {instruction}")]
    UnsupportedOperand { ip: u64, instruction: String },
    #[error("step limit must be greater than zero")]
    EmptyStepLimit,
    #[error("integer divide error at {0:#x}")]
    DivideError(u64),
    #[error("failed to execute instruction at {ip:#x}: {instruction}")]
    Execution {
        ip: u64,
        instruction: String,
        #[source]
        source: Box<CpuError>,
    },
}

impl CpuError {
    pub fn unsupported_instruction(&self) -> Option<&UnsupportedInstructionRecord> {
        match self {
            Self::UnsupportedInstruction { record } => Some(record),
            Self::Execution { source, .. } => source.unsupported_instruction(),
            _ => None,
        }
    }
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

#[derive(Debug, Clone, Default)]
pub struct ExecutionCache {
    ir: BlockCache,
    decoded: HashMap<BasicBlockId, Vec<Instruction>>,
}

impl ExecutionCache {
    pub fn stats(&self) -> BlockCacheStats {
        self.ir.stats()
    }

    pub fn clear(&mut self) {
        self.ir.clear();
        self.decoded.clear();
    }
}

pub struct Interpreter {
    memory: GuestMemory,
    registers: Registers,
    trace_enabled: bool,
    trace: Vec<TraceRecord>,
    cache: ExecutionCache,
}

impl Interpreter {
    pub fn new(memory: GuestMemory, registers: Registers) -> Self {
        Self::with_cache(memory, registers, ExecutionCache::default())
    }

    pub fn with_cache(memory: GuestMemory, registers: Registers, cache: ExecutionCache) -> Self {
        Self {
            memory,
            registers,
            trace_enabled: false,
            trace: Vec::new(),
            cache,
        }
    }

    pub fn memory(&self) -> &GuestMemory {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        &mut self.memory
    }

    pub fn registers(&self) -> &Registers {
        &self.registers
    }

    pub fn registers_mut(&mut self) -> &mut Registers {
        &mut self.registers
    }

    pub fn replace_state(&mut self, memory: GuestMemory, registers: Registers) {
        self.memory = memory;
        self.registers = registers;
        self.trace.clear();
        self.cache.clear();
    }

    pub fn into_parts(self) -> (GuestMemory, Registers, Vec<TraceRecord>) {
        (self.memory, self.registers, self.trace)
    }

    pub fn into_state(self) -> (GuestMemory, Registers, Vec<TraceRecord>, ExecutionCache) {
        (self.memory, self.registers, self.trace, self.cache)
    }

    pub fn set_trace_enabled(&mut self, enabled: bool) {
        self.trace_enabled = enabled;
    }

    pub fn trace(&self) -> &[TraceRecord] {
        &self.trace
    }

    pub fn cache_stats(&self) -> BlockCacheStats {
        self.cache.stats()
    }

    pub fn clear_block_cache(&mut self) {
        self.cache.clear();
    }

    pub fn current_instruction_record(&self) -> Result<UnsupportedInstructionRecord, CpuError> {
        let ip = self.registers.rip;
        let instruction = self.decode(ip)?;
        if instruction.code() == Code::INVALID {
            return Err(CpuError::InvalidInstruction(ip));
        }
        let text = format_instruction(&instruction);
        self.unsupported_instruction_record(&instruction, &text)
    }

    pub fn step(&mut self) -> Result<StepOutcome, CpuError> {
        let ip = self.registers.rip;
        let instruction = self.decode(ip)?;
        if instruction.code() == Code::INVALID {
            return Err(CpuError::InvalidInstruction(ip));
        }

        let text = format_instruction(&instruction);
        let before = self.registers;
        let outcome = self
            .execute(&instruction, &text)
            .map_err(|source| CpuError::Execution {
                ip,
                instruction: text.clone(),
                source: Box::new(source),
            })?;
        if self.trace_enabled {
            self.trace.push(TraceRecord {
                ip,
                instruction: text,
                before,
                after: self.registers,
            });
        }
        Ok(outcome)
    }

    pub fn step_block(&mut self) -> Result<StepOutcome, CpuError> {
        let start_ip = self.registers.rip;
        let (block, instructions) = self.cached_block(start_ip)?;
        for (index, instruction) in instructions.iter().enumerate() {
            if self.registers.rip != instruction.ip() {
                break;
            }
            let text = &block.instructions[index].text;
            let before = self.registers;
            let outcome =
                self.execute(instruction, text)
                    .map_err(|source| CpuError::Execution {
                        ip: instruction.ip(),
                        instruction: text.clone(),
                        source: Box::new(source),
                    })?;
            if self.trace_enabled {
                self.trace.push(TraceRecord {
                    ip: instruction.ip(),
                    instruction: text.clone(),
                    before,
                    after: self.registers,
                });
            }
            if outcome != StepOutcome::Continue
                || block.instructions[index].kind != IrInstructionKind::Compute
            {
                return Ok(outcome);
            }
        }
        Ok(StepOutcome::Continue)
    }

    pub fn run(&mut self, max_steps: u64) -> Result<RunOutcome, CpuError> {
        if max_steps == 0 {
            return Err(CpuError::EmptyStepLimit);
        }

        for _ in 0..max_steps {
            match self.step_block()? {
                StepOutcome::Continue => {}
                StepOutcome::Halted(code) => return Ok(RunOutcome::Exited(code)),
                StepOutcome::Syscall(trap) if trap.number == 60 || trap.number == 231 => {
                    return Ok(RunOutcome::Exited(trap.args[0] as i32));
                }
                StepOutcome::Syscall(trap) => return Ok(RunOutcome::Syscall(trap)),
            }
        }
        Ok(RunOutcome::StepLimit)
    }

    fn decode(&self, ip: u64) -> Result<Instruction, CpuError> {
        let bytes = self.memory.fetch_bytes(ip, MAX_INSTRUCTION_LEN)?;
        let mut decoder = Decoder::with_ip(64, &bytes, ip, DecoderOptions::NONE);
        Ok(decoder.decode())
    }

    fn cached_block(&mut self, ip: u64) -> Result<(BasicBlock, Vec<Instruction>), CpuError> {
        let id = BasicBlockId(ip);
        if let Some(block) = self.cache.ir.get(id) {
            if let Some(decoded) = self.cache.decoded.get(&id) {
                return Ok((block, decoded.clone()));
            }
        }
        let (block, decoded) = self.translate_block(ip)?;
        self.cache.ir.insert(block.clone());
        self.cache.decoded.insert(id, decoded.clone());
        Ok((block, decoded))
    }

    fn translate_block(&self, start_ip: u64) -> Result<(BasicBlock, Vec<Instruction>), CpuError> {
        let mut ip = start_ip;
        let mut ir = Vec::new();
        let mut decoded = Vec::new();
        let mut terminator = BlockTerminator::FallThrough;
        for _ in 0..MAX_BLOCK_INSTRUCTIONS {
            let instruction = self.decode(ip)?;
            if instruction.code() == Code::INVALID {
                return Err(CpuError::InvalidInstruction(ip));
            }
            let kind = instruction_kind(&instruction);
            terminator = block_terminator(kind);
            ir.push(IrInstruction {
                ip,
                len: instruction.len() as u8,
                text: format_instruction(&instruction),
                kind,
            });
            ip = instruction.next_ip();
            decoded.push(instruction);
            if kind != IrInstructionKind::Compute {
                break;
            }
        }
        Ok((BasicBlock::new(start_ip, ir, terminator), decoded))
    }

    fn execute(&mut self, instruction: &Instruction, text: &str) -> Result<StepOutcome, CpuError> {
        let next_ip = instruction.next_ip();
        let mut rip_written = false;
        let outcome = match instruction.mnemonic() {
            Mnemonic::Mov => {
                let width = self.destination_width(instruction, 0)?;
                let value = self.read_operand(instruction, 1, width)?;
                self.write_operand(instruction, 0, value, width)?;
                StepOutcome::Continue
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                let destination_width = self.destination_width(instruction, 0)?;
                let source_width = self.source_width(instruction, 1)?;
                let value = self.read_operand(instruction, 1, source_width)?;
                self.write_operand(
                    instruction,
                    0,
                    sign_extend(value, source_width),
                    destination_width,
                )?;
                StepOutcome::Continue
            }
            Mnemonic::Movzx => {
                let destination_width = self.destination_width(instruction, 0)?;
                let source_width = self.source_width(instruction, 1)?;
                let value = self.read_operand(instruction, 1, source_width)?;
                self.write_operand(instruction, 0, value, destination_width)?;
                StepOutcome::Continue
            }
            Mnemonic::Movd => {
                self.execute_mov_simd_scalar(instruction, 32)?;
                StepOutcome::Continue
            }
            Mnemonic::Movq => {
                self.execute_mov_simd_scalar(instruction, 64)?;
                StepOutcome::Continue
            }
            Mnemonic::Xchg => {
                self.execute_xchg(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Movdqa | Mnemonic::Movdqu | Mnemonic::Movups | Mnemonic::Movaps => {
                self.execute_xmm_move(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Punpcklqdq => {
                self.execute_punpcklqdq(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd => {
                self.execute_xmm_binary(instruction, XmmBinaryOp::Xor)?;
                StepOutcome::Continue
            }
            Mnemonic::Por | Mnemonic::Orps | Mnemonic::Orpd => {
                self.execute_xmm_binary(instruction, XmmBinaryOp::Or)?;
                StepOutcome::Continue
            }
            Mnemonic::Pand | Mnemonic::Andps | Mnemonic::Andpd => {
                self.execute_xmm_binary(instruction, XmmBinaryOp::And)?;
                StepOutcome::Continue
            }
            Mnemonic::Pshufd => {
                self.execute_pshufd(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Shufps => {
                self.execute_shufps(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Pslld | Mnemonic::Psrld | Mnemonic::Psllq | Mnemonic::Psrlq => {
                self.execute_packed_shift(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => {
                self.execute_stos(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq => {
                self.execute_movs(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Cbw => {
                let ax = sign_extend(self.registers.rax & 0xff, 8) & 0xffff;
                self.registers.write(Register::AX, ax)?;
                StepOutcome::Continue
            }
            Mnemonic::Cwde => {
                let eax = sign_extend(self.registers.rax & 0xffff, 16) & 0xffff_ffff;
                self.registers.write(Register::EAX, eax)?;
                StepOutcome::Continue
            }
            Mnemonic::Cdqe => {
                self.registers.rax = sign_extend(self.registers.rax & 0xffff_ffff, 32);
                StepOutcome::Continue
            }
            Mnemonic::Cwd => {
                let sign = (self.registers.rax & 0x8000) != 0;
                self.registers
                    .write(Register::DX, if sign { 0xffff } else { 0 })?;
                StepOutcome::Continue
            }
            Mnemonic::Cdq => {
                let sign = (self.registers.rax & 0x8000_0000) != 0;
                self.registers
                    .write(Register::EDX, if sign { 0xffff_ffff } else { 0 })?;
                StepOutcome::Continue
            }
            Mnemonic::Cqo => {
                self.registers.rdx = if self.registers.rax & (1 << 63) != 0 {
                    u64::MAX
                } else {
                    0
                };
                StepOutcome::Continue
            }
            Mnemonic::Lea => {
                let address = self.effective_address(instruction)?;
                let width = self.destination_width(instruction, 0)?;
                self.write_operand(instruction, 0, address, width)?;
                StepOutcome::Continue
            }
            Mnemonic::Add => {
                self.execute_binary(instruction, BinaryOp::Add)?;
                StepOutcome::Continue
            }
            Mnemonic::Sub => {
                self.execute_binary(instruction, BinaryOp::Sub)?;
                StepOutcome::Continue
            }
            Mnemonic::Adc => {
                self.execute_binary(instruction, BinaryOp::Adc)?;
                StepOutcome::Continue
            }
            Mnemonic::Sbb => {
                self.execute_binary(instruction, BinaryOp::Sbb)?;
                StepOutcome::Continue
            }
            Mnemonic::Xor => {
                self.execute_binary(instruction, BinaryOp::Xor)?;
                StepOutcome::Continue
            }
            Mnemonic::And => {
                self.execute_binary(instruction, BinaryOp::And)?;
                StepOutcome::Continue
            }
            Mnemonic::Or => {
                self.execute_binary(instruction, BinaryOp::Or)?;
                StepOutcome::Continue
            }
            Mnemonic::Neg => {
                self.execute_unary(instruction, UnaryOp::Neg)?;
                StepOutcome::Continue
            }
            Mnemonic::Not => {
                self.execute_unary(instruction, UnaryOp::Not)?;
                StepOutcome::Continue
            }
            Mnemonic::Inc => {
                self.execute_unary(instruction, UnaryOp::Inc)?;
                StepOutcome::Continue
            }
            Mnemonic::Dec => {
                self.execute_unary(instruction, UnaryOp::Dec)?;
                StepOutcome::Continue
            }
            Mnemonic::Bswap => {
                self.execute_bswap(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Shl | Mnemonic::Sal => {
                self.execute_shift(instruction, ShiftOp::Shl)?;
                StepOutcome::Continue
            }
            Mnemonic::Shld => {
                self.execute_double_shift(instruction, DoubleShiftOp::Shld)?;
                StepOutcome::Continue
            }
            Mnemonic::Shr => {
                self.execute_shift(instruction, ShiftOp::Shr)?;
                StepOutcome::Continue
            }
            Mnemonic::Shrd => {
                self.execute_double_shift(instruction, DoubleShiftOp::Shrd)?;
                StepOutcome::Continue
            }
            Mnemonic::Sar => {
                self.execute_shift(instruction, ShiftOp::Sar)?;
                StepOutcome::Continue
            }
            Mnemonic::Bt => {
                self.execute_bit_test(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Bsf => {
                self.execute_bit_scan(instruction, BitScanOp::Forward)?;
                StepOutcome::Continue
            }
            Mnemonic::Bsr => {
                self.execute_bit_scan(instruction, BitScanOp::Reverse)?;
                StepOutcome::Continue
            }
            Mnemonic::Mul => {
                self.execute_mul(instruction, false)?;
                StepOutcome::Continue
            }
            Mnemonic::Imul => {
                self.execute_imul(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Div => {
                self.execute_div(instruction, false)?;
                StepOutcome::Continue
            }
            Mnemonic::Idiv => {
                self.execute_div(instruction, true)?;
                StepOutcome::Continue
            }
            mnemonic if is_cmovcc(mnemonic) => {
                if self.condition_passed(mnemonic)? {
                    let width = self.destination_width(instruction, 0)?;
                    let value = self.read_operand(instruction, 1, width)?;
                    self.write_operand(instruction, 0, value, width)?;
                }
                StepOutcome::Continue
            }
            mnemonic if is_setcc(mnemonic) => {
                let value = u64::from(self.condition_passed(mnemonic)?);
                self.write_operand(instruction, 0, value, 8)?;
                StepOutcome::Continue
            }
            Mnemonic::Cmp => {
                let width = self.destination_width(instruction, 0)?;
                let left = self.read_operand(instruction, 0, width)?;
                let right = self.read_operand(instruction, 1, width)?;
                self.set_sub_flags(left, right, left.wrapping_sub(right), width);
                StepOutcome::Continue
            }
            Mnemonic::Cmpxchg => {
                self.execute_cmpxchg(instruction)?;
                StepOutcome::Continue
            }
            Mnemonic::Test => {
                let width = self.destination_width(instruction, 0)?;
                let left = self.read_operand(instruction, 0, width)?;
                let right = self.read_operand(instruction, 1, width)?;
                self.set_logic_flags(left & right, width);
                StepOutcome::Continue
            }
            Mnemonic::Jmp => {
                let target = self.branch_target(instruction, 0)?;
                self.registers.rip = target;
                rip_written = true;
                StepOutcome::Continue
            }
            mnemonic if is_jcc(mnemonic) => {
                if self.condition_passed(mnemonic)? {
                    self.registers.rip = self.branch_target(instruction, 0)?;
                    rip_written = true;
                }
                StepOutcome::Continue
            }
            Mnemonic::Call => {
                let target = self.branch_target(instruction, 0)?;
                self.push_u64(next_ip)?;
                self.registers.rip = target;
                rip_written = true;
                StepOutcome::Continue
            }
            Mnemonic::Ret => {
                let target = self.pop_u64()?;
                if instruction.op_count() == 1 {
                    self.registers.rsp = self
                        .registers
                        .rsp
                        .wrapping_add(u64::from(instruction.immediate16()));
                }
                self.registers.rip = target;
                rip_written = true;
                StepOutcome::Continue
            }
            Mnemonic::Push => {
                let value = self.read_operand(instruction, 0, 64)?;
                self.push_u64(value)?;
                StepOutcome::Continue
            }
            Mnemonic::Pop => {
                let value = self.pop_u64()?;
                let width = self.destination_width(instruction, 0)?;
                self.write_operand(instruction, 0, value, width)?;
                StepOutcome::Continue
            }
            Mnemonic::Nop => StepOutcome::Continue,
            Mnemonic::Syscall => {
                self.registers.rcx = next_ip;
                self.registers.r11 = self.registers.rflags;
                self.registers.rip = next_ip;
                rip_written = true;
                StepOutcome::Syscall(SyscallTrap {
                    number: self.registers.rax,
                    args: [
                        self.registers.rdi,
                        self.registers.rsi,
                        self.registers.rdx,
                        self.registers.r10,
                        self.registers.r8,
                        self.registers.r9,
                    ],
                })
            }
            _ => {
                return Err(CpuError::UnsupportedInstruction {
                    record: self.unsupported_instruction_record(instruction, text)?,
                })
            }
        };

        if !rip_written {
            self.registers.rip = next_ip;
        }
        Ok(outcome)
    }

    fn unsupported_instruction_record(
        &self,
        instruction: &Instruction,
        text: &str,
    ) -> Result<UnsupportedInstructionRecord, CpuError> {
        let raw_bytes = self
            .memory
            .fetch_bytes(instruction.ip(), instruction.len())?;
        let (mnemonic, operands) = split_instruction(text);
        Ok(UnsupportedInstructionRecord {
            ip: instruction.ip(),
            raw_bytes,
            mnemonic,
            operands,
            text: text.to_string(),
            registers: self.registers,
        })
    }

    fn execute_binary(&mut self, instruction: &Instruction, op: BinaryOp) -> Result<(), CpuError> {
        let width = self.destination_width(instruction, 0)?;
        let left = self.read_operand(instruction, 0, width)?;
        let right = self.read_operand(instruction, 1, width)?;
        let result = match op {
            BinaryOp::Add => {
                let result = left.wrapping_add(right);
                self.set_add_flags(left, right, result, width);
                result
            }
            BinaryOp::Sub => {
                let result = left.wrapping_sub(right);
                self.set_sub_flags(left, right, result, width);
                result
            }
            BinaryOp::Adc => {
                let carry = u64::from(self.registers.flag(FLAG_CF));
                let result = left.wrapping_add(right).wrapping_add(carry);
                self.set_add_flags(left, right.wrapping_add(carry), result, width);
                result
            }
            BinaryOp::Sbb => {
                let borrow = u64::from(self.registers.flag(FLAG_CF));
                let result = left.wrapping_sub(right).wrapping_sub(borrow);
                self.set_sub_flags(left, right.wrapping_add(borrow), result, width);
                result
            }
            BinaryOp::Xor => {
                let result = left ^ right;
                self.set_logic_flags(result, width);
                result
            }
            BinaryOp::And => {
                let result = left & right;
                self.set_logic_flags(result, width);
                result
            }
            BinaryOp::Or => {
                let result = left | right;
                self.set_logic_flags(result, width);
                result
            }
        };
        self.write_operand(instruction, 0, result, width)?;
        Ok(())
    }

    fn execute_unary(&mut self, instruction: &Instruction, op: UnaryOp) -> Result<(), CpuError> {
        let width = self.destination_width(instruction, 0)?;
        let value = self.read_operand(instruction, 0, width)? & mask(width);
        let result = match op {
            UnaryOp::Neg => {
                let result = 0u64.wrapping_sub(value) & mask(width);
                self.registers.set_flag(FLAG_CF, value != 0);
                self.registers.set_flag(FLAG_OF, value == sign_bit(width));
                self.set_common_flags(result, width);
                result
            }
            UnaryOp::Not => !value & mask(width),
            UnaryOp::Inc => {
                let result = value.wrapping_add(1) & mask(width);
                self.registers
                    .set_flag(FLAG_OF, value == (sign_bit(width) - 1));
                self.set_common_flags(result, width);
                result
            }
            UnaryOp::Dec => {
                let result = value.wrapping_sub(1) & mask(width);
                self.registers.set_flag(FLAG_OF, value == sign_bit(width));
                self.set_common_flags(result, width);
                result
            }
        };
        self.write_operand(instruction, 0, result, width)?;
        Ok(())
    }

    fn execute_bswap(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let width = self.destination_width(instruction, 0)?;
        let value = self.read_operand(instruction, 0, width)? & mask(width);
        let result = match width {
            32 => u64::from((value as u32).swap_bytes()),
            64 => value.swap_bytes(),
            _ => {
                return Err(CpuError::UnsupportedOperand {
                    ip: instruction.ip(),
                    instruction: format_instruction(instruction),
                });
            }
        };
        self.write_operand(instruction, 0, result, width)?;
        Ok(())
    }

    fn execute_mov_simd_scalar(
        &mut self,
        instruction: &Instruction,
        width: u32,
    ) -> Result<(), CpuError> {
        match (instruction.op_kind(0), instruction.op_kind(1)) {
            (OpKind::Register, _) if xmm_index(instruction.op_register(0)).is_some() => {
                let value = self.read_simd_scalar_source(instruction, 1, width)?;
                let index = xmm_index(instruction.op_register(0)).expect("checked above");
                self.registers.xmm[index] = u128::from(value);
            }
            (_, OpKind::Register) if xmm_index(instruction.op_register(1)).is_some() => {
                let index = xmm_index(instruction.op_register(1)).expect("checked above");
                let value = self.registers.xmm[index] as u64 & mask(width);
                self.write_simd_scalar_destination(instruction, 0, value, width)?;
            }
            _ => {
                let value = self.read_operand(instruction, 1, width)?;
                self.write_operand(instruction, 0, value, width)?;
            }
        }
        Ok(())
    }

    fn execute_xchg(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let width = self.destination_width(instruction, 0)?;
        let left = self.read_operand(instruction, 0, width)?;
        let right = self.read_operand(instruction, 1, width)?;
        self.write_operand(instruction, 0, right, width)?;
        self.write_operand(instruction, 1, left, width)?;
        Ok(())
    }

    fn read_simd_scalar_source(
        &self,
        instruction: &Instruction,
        op_index: u32,
        width: u32,
    ) -> Result<u64, CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::Register => {
                let register = instruction.op_register(op_index);
                if let Some(index) = xmm_index(register) {
                    Ok(self.registers.xmm[index] as u64 & mask(width))
                } else {
                    Ok(self.registers.read(register)?)
                }
            }
            OpKind::Memory => {
                let bytes = self
                    .memory
                    .read_bytes(self.effective_address(instruction)?, (width / 8) as usize)?;
                Ok(little_endian_to_u64(&bytes))
            }
            _ => self.read_operand(instruction, op_index, width),
        }
    }

    fn write_simd_scalar_destination(
        &mut self,
        instruction: &Instruction,
        op_index: u32,
        value: u64,
        width: u32,
    ) -> Result<(), CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::Register => {
                let register = instruction.op_register(op_index);
                if let Some(index) = xmm_index(register) {
                    self.registers.xmm[index] = u128::from(value & mask(width));
                    Ok(())
                } else {
                    self.registers.write(register, value & mask(width))?;
                    Ok(())
                }
            }
            OpKind::Memory => {
                let address = self.effective_address(instruction)?;
                self.memory
                    .write_bytes(address, &u64_to_little_endian(value, (width / 8) as usize))?;
                Ok(())
            }
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn execute_xmm_move(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let value = self.read_xmm_operand(instruction, 1)?;
        self.write_xmm_operand(instruction, 0, value)
    }

    fn execute_punpcklqdq(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let destination = self.read_xmm_operand(instruction, 0)?;
        let source = self.read_xmm_operand(instruction, 1)?;
        let low = destination & u128::from(u64::MAX);
        let high = (source & u128::from(u64::MAX)) << 64;
        self.write_xmm_operand(instruction, 0, high | low)
    }

    fn execute_xmm_binary(
        &mut self,
        instruction: &Instruction,
        op: XmmBinaryOp,
    ) -> Result<(), CpuError> {
        let left = self.read_xmm_operand(instruction, 0)?;
        let right = self.read_xmm_operand(instruction, 1)?;
        let result = match op {
            XmmBinaryOp::Xor => left ^ right,
            XmmBinaryOp::Or => left | right,
            XmmBinaryOp::And => left & right,
        };
        self.write_xmm_operand(instruction, 0, result)
    }

    fn execute_pshufd(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let source = self.read_xmm_operand(instruction, 1)?;
        let control = self.read_operand(instruction, 2, 8)? as u8;
        let mut result = 0u128;
        for lane in 0..4 {
            let source_lane = (control >> (lane * 2)) & 0b11;
            let value = (source >> (u32::from(source_lane) * 32)) & 0xffff_ffff;
            result |= value << (lane * 32);
        }
        self.write_xmm_operand(instruction, 0, result)
    }

    fn execute_shufps(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let destination = self.read_xmm_operand(instruction, 0)?;
        let source = self.read_xmm_operand(instruction, 1)?;
        let control = self.read_operand(instruction, 2, 8)? as u8;
        let selectors = [
            control & 0b11,
            (control >> 2) & 0b11,
            (control >> 4) & 0b11,
            (control >> 6) & 0b11,
        ];
        let mut result = 0u128;
        for lane in 0..2 {
            let value = (destination >> (u32::from(selectors[lane]) * 32)) & 0xffff_ffff;
            result |= value << (lane * 32);
        }
        for lane in 2..4 {
            let value = (source >> (u32::from(selectors[lane]) * 32)) & 0xffff_ffff;
            result |= value << (lane * 32);
        }
        self.write_xmm_operand(instruction, 0, result)
    }

    fn execute_packed_shift(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let value = self.read_xmm_operand(instruction, 0)?;
        let count = self.read_packed_shift_count(instruction)?;
        let (lane_width, left) = match instruction.mnemonic() {
            Mnemonic::Pslld => (32, true),
            Mnemonic::Psrld => (32, false),
            Mnemonic::Psllq => (64, true),
            Mnemonic::Psrlq => (64, false),
            _ => unreachable!("checked by caller"),
        };
        let lane_mask = if lane_width == 32 {
            0xffff_ffffu128
        } else {
            u128::from(u64::MAX)
        };
        let lanes = 128 / lane_width;
        let mut result = 0u128;
        for lane in 0..lanes {
            let shift = lane * lane_width;
            let lane_value = (value >> shift) & lane_mask;
            let shifted = if count >= lane_width {
                0
            } else if left {
                (lane_value << count) & lane_mask
            } else {
                lane_value >> count
            };
            result |= shifted << shift;
        }
        self.write_xmm_operand(instruction, 0, result)
    }

    fn read_packed_shift_count(&self, instruction: &Instruction) -> Result<u32, CpuError> {
        match instruction.op_kind(1) {
            OpKind::Immediate8 => Ok(u32::from(instruction.immediate8())),
            OpKind::Register | OpKind::Memory => {
                Ok((self.read_xmm_operand(instruction, 1)? & 0xff) as u32)
            }
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn read_xmm_operand(&self, instruction: &Instruction, op_index: u32) -> Result<u128, CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::Register => {
                let register = instruction.op_register(op_index);
                let index = xmm_index(register).ok_or_else(|| CpuError::UnsupportedOperand {
                    ip: instruction.ip(),
                    instruction: format_instruction(instruction),
                })?;
                Ok(self.registers.xmm[index])
            }
            OpKind::Memory => {
                let bytes = self
                    .memory
                    .read_bytes(self.effective_address(instruction)?, 16)?;
                Ok(u128::from_le_bytes(
                    bytes.try_into().expect("xmm read length"),
                ))
            }
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn write_xmm_operand(
        &mut self,
        instruction: &Instruction,
        op_index: u32,
        value: u128,
    ) -> Result<(), CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::Register => {
                let register = instruction.op_register(op_index);
                let index = xmm_index(register).ok_or_else(|| CpuError::UnsupportedOperand {
                    ip: instruction.ip(),
                    instruction: format_instruction(instruction),
                })?;
                self.registers.xmm[index] = value;
                Ok(())
            }
            OpKind::Memory => {
                let address = self.effective_address(instruction)?;
                self.memory.write_bytes(address, &value.to_le_bytes())?;
                Ok(())
            }
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn execute_stos(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let size = match instruction.mnemonic() {
            Mnemonic::Stosb => 1,
            Mnemonic::Stosw => 2,
            Mnemonic::Stosd => 4,
            Mnemonic::Stosq => 8,
            _ => unreachable!("checked by caller"),
        };
        let count = if instruction.has_rep_prefix() {
            self.registers.rcx
        } else {
            1
        };
        let step = if self.registers.flag(FLAG_DF) {
            -(size as i64)
        } else {
            size as i64
        };
        let bytes = u64_to_little_endian(self.registers.rax, size);
        let mut address = self
            .segment_base(instruction.memory_segment())
            .wrapping_add(self.registers.rdi);
        for _ in 0..count {
            self.memory.write_bytes(address, &bytes)?;
            address = address.wrapping_add_signed(step);
        }
        self.registers.rdi = address.wrapping_sub(self.segment_base(instruction.memory_segment()));
        if instruction.has_rep_prefix() {
            self.registers.rcx = 0;
        }
        Ok(())
    }

    fn execute_movs(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let size = match instruction.mnemonic() {
            Mnemonic::Movsb => 1,
            Mnemonic::Movsw => 2,
            Mnemonic::Movsd => 4,
            Mnemonic::Movsq => 8,
            _ => unreachable!("checked by caller"),
        };
        let count = if instruction.has_rep_prefix() {
            self.registers.rcx
        } else {
            1
        };
        let step = if self.registers.flag(FLAG_DF) {
            -(size as i64)
        } else {
            size as i64
        };
        let source_base = self.segment_base(instruction.memory_segment());
        let mut source = source_base.wrapping_add(self.registers.rsi);
        let mut destination = self.registers.rdi;
        for _ in 0..count {
            let bytes = self.memory.read_bytes(source, size)?;
            self.memory.write_bytes(destination, &bytes)?;
            source = source.wrapping_add_signed(step);
            destination = destination.wrapping_add_signed(step);
        }
        self.registers.rsi = source.wrapping_sub(source_base);
        self.registers.rdi = destination;
        if instruction.has_rep_prefix() {
            self.registers.rcx = 0;
        }
        Ok(())
    }

    fn execute_bit_test(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let width = self.destination_width(instruction, 0)?;
        let base = self.read_operand(instruction, 0, width)?;
        let bit = self.read_operand(instruction, 1, width)? % u64::from(width);
        self.registers.set_flag(FLAG_CF, ((base >> bit) & 1) != 0);
        Ok(())
    }

    fn execute_mul(&mut self, instruction: &Instruction, signed: bool) -> Result<(), CpuError> {
        let width = self.source_width(instruction, 0)?;
        let rhs = self.read_operand(instruction, 0, width)? & mask(width);
        let low = self.registers.rax & mask(width);
        let result = if signed {
            let left = sign_extend(low, width) as i128;
            let right = sign_extend(rhs, width) as i128;
            (left * right) as u128
        } else {
            u128::from(low) * u128::from(rhs)
        };
        self.write_mul_result(width, result);
        let overflow = if signed {
            let truncated = result as u64 & mask(width);
            result as i128 != sign_extend(truncated, width) as i128
        } else {
            (result >> width) != 0
        };
        self.registers.set_flag(FLAG_CF, overflow);
        self.registers.set_flag(FLAG_OF, overflow);
        Ok(())
    }

    fn execute_imul(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        match instruction.op_count() {
            1 => self.execute_mul(instruction, true),
            2 | 3 => {
                let width = self.destination_width(instruction, 0)?;
                let left = if instruction.op_count() == 3 {
                    self.read_operand(instruction, 1, width)?
                } else {
                    self.read_operand(instruction, 0, width)?
                };
                let right = if instruction.op_count() == 3 {
                    self.read_operand(instruction, 2, width)?
                } else {
                    self.read_operand(instruction, 1, width)?
                };
                let result = (sign_extend(left, width) as i128)
                    .wrapping_mul(sign_extend(right, width) as i128);
                let truncated = result as u64 & mask(width);
                self.write_operand(instruction, 0, truncated, width)?;
                let overflow = result != sign_extend(truncated, width) as i128;
                self.registers.set_flag(FLAG_CF, overflow);
                self.registers.set_flag(FLAG_OF, overflow);
                Ok(())
            }
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn execute_div(&mut self, instruction: &Instruction, signed: bool) -> Result<(), CpuError> {
        let width = self.source_width(instruction, 0)?;
        let divisor = self.read_operand(instruction, 0, width)? & mask(width);
        if divisor == 0 {
            return Err(CpuError::DivideError(instruction.ip()));
        }
        if signed {
            let divisor = sign_extend(divisor, width) as i128;
            let dividend = self.signed_dividend(width);
            let quotient = dividend / divisor;
            let remainder = dividend % divisor;
            if quotient < signed_min(width) || quotient > signed_max(width) {
                return Err(CpuError::DivideError(instruction.ip()));
            }
            self.write_div_result(width, quotient as u64, remainder as u64)?;
        } else {
            let dividend = self.unsigned_dividend(width);
            let quotient = dividend / u128::from(divisor);
            let remainder = dividend % u128::from(divisor);
            if quotient > u128::from(mask(width)) {
                return Err(CpuError::DivideError(instruction.ip()));
            }
            self.write_div_result(width, quotient as u64, remainder as u64)?;
        }
        Ok(())
    }

    fn write_mul_result(&mut self, width: u32, result: u128) {
        match width {
            8 => {
                self.registers.rax = (self.registers.rax & !0xffff) | (result as u64 & 0xffff);
            }
            16 => {
                let _ = self.registers.write(Register::AX, result as u64);
                let _ = self.registers.write(Register::DX, (result >> 16) as u64);
            }
            32 => {
                let _ = self.registers.write(Register::EAX, result as u64);
                let _ = self.registers.write(Register::EDX, (result >> 32) as u64);
            }
            _ => {
                self.registers.rax = result as u64;
                self.registers.rdx = (result >> 64) as u64;
            }
        }
    }

    fn write_div_result(
        &mut self,
        width: u32,
        quotient: u64,
        remainder: u64,
    ) -> Result<(), CpuError> {
        match width {
            8 => {
                self.registers.write(Register::AL, quotient)?;
                self.registers.write(Register::AH, remainder)?;
            }
            16 => {
                self.registers.write(Register::AX, quotient)?;
                self.registers.write(Register::DX, remainder)?;
            }
            32 => {
                self.registers.write(Register::EAX, quotient)?;
                self.registers.write(Register::EDX, remainder)?;
            }
            _ => {
                self.registers.rax = quotient;
                self.registers.rdx = remainder;
            }
        }
        Ok(())
    }

    fn unsigned_dividend(&self, width: u32) -> u128 {
        match width {
            8 => u128::from(self.registers.rax & 0xffff),
            16 => u128::from(((self.registers.rdx & 0xffff) << 16) | (self.registers.rax & 0xffff)),
            32 => u128::from(
                ((self.registers.rdx & 0xffff_ffff) << 32) | (self.registers.rax & 0xffff_ffff),
            ),
            _ => (u128::from(self.registers.rdx) << 64) | u128::from(self.registers.rax),
        }
    }

    fn signed_dividend(&self, width: u32) -> i128 {
        match width {
            8 => sign_extend(self.registers.rax & 0xffff, 16) as i128,
            16 => sign_extend(
                ((self.registers.rdx & 0xffff) << 16) | (self.registers.rax & 0xffff),
                32,
            ) as i128,
            32 => sign_extend(
                ((self.registers.rdx & 0xffff_ffff) << 32) | (self.registers.rax & 0xffff_ffff),
                64,
            ) as i128,
            _ => {
                let combined =
                    (u128::from(self.registers.rdx) << 64) | u128::from(self.registers.rax);
                combined as i128
            }
        }
    }

    fn execute_shift(&mut self, instruction: &Instruction, op: ShiftOp) -> Result<(), CpuError> {
        let width = self.destination_width(instruction, 0)?;
        let value = self.read_operand(instruction, 0, width)? & mask(width);
        let count = self.read_operand(instruction, 1, 8)? & if width == 64 { 0x3f } else { 0x1f };
        if count == 0 {
            return Ok(());
        }

        let result = match op {
            ShiftOp::Shl => value.wrapping_shl(count as u32) & mask(width),
            ShiftOp::Shr => value.wrapping_shr(count as u32),
            ShiftOp::Sar => {
                let signed = sign_extend(value, width) as i64;
                (signed >> count) as u64 & mask(width)
            }
        };
        let carry = match op {
            ShiftOp::Shl if count <= u64::from(width) => {
                ((value >> (width - count as u32)) & 1) != 0
            }
            ShiftOp::Shr | ShiftOp::Sar if count <= u64::from(width) => {
                ((value >> (count - 1)) & 1) != 0
            }
            _ => false,
        };
        self.registers.set_flag(FLAG_CF, carry);
        if count == 1 {
            let overflow = match op {
                ShiftOp::Shl => ((result ^ value) & sign_bit(width)) != 0,
                ShiftOp::Shr => (value & sign_bit(width)) != 0,
                ShiftOp::Sar => false,
            };
            self.registers.set_flag(FLAG_OF, overflow);
        }
        self.set_common_flags(result, width);
        self.write_operand(instruction, 0, result, width)?;
        Ok(())
    }

    fn execute_double_shift(
        &mut self,
        instruction: &Instruction,
        op: DoubleShiftOp,
    ) -> Result<(), CpuError> {
        let width = self.destination_width(instruction, 0)?;
        let value = self.read_operand(instruction, 0, width)? & mask(width);
        let source = self.read_operand(instruction, 1, width)? & mask(width);
        let count = self.read_operand(instruction, 2, 8)? & if width == 64 { 0x3f } else { 0x1f };
        if count == 0 {
            return Ok(());
        }

        let width_bits = u64::from(width);
        let result = match op {
            DoubleShiftOp::Shld => {
                ((value << count) | (source >> (width_bits - count))) & mask(width)
            }
            DoubleShiftOp::Shrd => {
                ((value >> count) | (source << (width_bits - count))) & mask(width)
            }
        };
        let carry = match op {
            DoubleShiftOp::Shld => ((value >> (width - count as u32)) & 1) != 0,
            DoubleShiftOp::Shrd => ((value >> (count - 1)) & 1) != 0,
        };
        self.registers.set_flag(FLAG_CF, carry);
        if count == 1 {
            self.registers
                .set_flag(FLAG_OF, ((result ^ value) & sign_bit(width)) != 0);
        }
        self.set_common_flags(result, width);
        self.write_operand(instruction, 0, result, width)?;
        Ok(())
    }

    fn execute_cmpxchg(&mut self, instruction: &Instruction) -> Result<(), CpuError> {
        let width = self.destination_width(instruction, 0)?;
        let destination = self.read_operand(instruction, 0, width)? & mask(width);
        let accumulator = self.accumulator(width)?;
        let source = self.read_operand(instruction, 1, width)? & mask(width);
        let result = accumulator.wrapping_sub(destination);
        self.set_sub_flags(accumulator, destination, result, width);
        if accumulator == destination {
            self.write_operand(instruction, 0, source, width)?;
        } else {
            self.write_accumulator(width, destination)?;
        }
        Ok(())
    }

    fn execute_bit_scan(
        &mut self,
        instruction: &Instruction,
        op: BitScanOp,
    ) -> Result<(), CpuError> {
        let width = self.source_width(instruction, 1)?;
        let source = self.read_operand(instruction, 1, width)? & mask(width);
        if source == 0 {
            self.registers.set_flag(FLAG_ZF, true);
            return Ok(());
        }

        let index = match op {
            BitScanOp::Forward => u64::from(source.trailing_zeros()),
            BitScanOp::Reverse => u64::from((u64::BITS - 1) - source.leading_zeros()),
        };
        let destination_width = self.destination_width(instruction, 0)?;
        self.write_operand(instruction, 0, index, destination_width)?;
        self.registers.set_flag(FLAG_ZF, false);
        Ok(())
    }

    fn accumulator(&self, width: u32) -> Result<u64, CpuError> {
        let register = match width {
            8 => Register::AL,
            16 => Register::AX,
            32 => Register::EAX,
            _ => Register::RAX,
        };
        Ok(self.registers.read(register)?)
    }

    fn write_accumulator(&mut self, width: u32, value: u64) -> Result<(), CpuError> {
        let register = match width {
            8 => Register::AL,
            16 => Register::AX,
            32 => Register::EAX,
            _ => Register::RAX,
        };
        self.registers.write(register, value)?;
        Ok(())
    }

    fn read_operand(
        &self,
        instruction: &Instruction,
        op_index: u32,
        width: u32,
    ) -> Result<u64, CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::Register => Ok(self.registers.read(instruction.op_register(op_index))?),
            OpKind::Immediate8 => Ok(u64::from(instruction.immediate8())),
            OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                Ok(sign_extend(instruction.immediate8() as u64, 8))
            }
            OpKind::Immediate16 => Ok(u64::from(instruction.immediate16())),
            OpKind::Immediate32 => Ok(u64::from(instruction.immediate32())),
            OpKind::Immediate32to64 => Ok(sign_extend(instruction.immediate32() as u64, 32)),
            OpKind::Immediate64 => Ok(instruction.immediate64()),
            OpKind::Memory => {
                let size = memory_size(instruction, width)?;
                let bytes = self
                    .memory
                    .read_bytes(self.effective_address(instruction)?, size)?;
                Ok(little_endian_to_u64(&bytes))
            }
            OpKind::NearBranch16 => Ok(u64::from(instruction.near_branch16())),
            OpKind::NearBranch32 => Ok(u64::from(instruction.near_branch32())),
            OpKind::NearBranch64 => Ok(instruction.near_branch64()),
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn write_operand(
        &mut self,
        instruction: &Instruction,
        op_index: u32,
        value: u64,
        width: u32,
    ) -> Result<(), CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::Register => {
                self.registers
                    .write(instruction.op_register(op_index), value & mask(width))?;
            }
            OpKind::Memory => {
                let size = memory_size(instruction, width)?;
                let address = self.effective_address(instruction)?;
                let bytes = u64_to_little_endian(value, size);
                let invalidate_cache = self
                    .memory
                    .permissions_at(address)
                    .map(MemoryPermission::executable)
                    .unwrap_or(false);
                self.memory.write_bytes(address, &bytes)?;
                if invalidate_cache {
                    self.cache.clear();
                }
            }
            _ => {
                return Err(CpuError::UnsupportedOperand {
                    ip: instruction.ip(),
                    instruction: format_instruction(instruction),
                })
            }
        }
        Ok(())
    }

    fn destination_width(&self, instruction: &Instruction, op_index: u32) -> Result<u32, CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::Register => Ok(register_width(instruction.op_register(op_index))?),
            OpKind::Memory => Ok((memory_size(instruction, 64)? * 8) as u32),
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn source_width(&self, instruction: &Instruction, op_index: u32) -> Result<u32, CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::Register => Ok(register_width(instruction.op_register(op_index))?),
            OpKind::Memory => Ok((memory_size(instruction, 64)? * 8) as u32),
            OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64 => Ok(8),
            OpKind::Immediate16 => Ok(16),
            OpKind::Immediate32 | OpKind::Immediate32to64 => Ok(32),
            OpKind::Immediate64 => Ok(64),
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn effective_address(&self, instruction: &Instruction) -> Result<u64, CpuError> {
        if instruction.is_ip_rel_memory_operand() {
            return Ok(self
                .segment_base(instruction.memory_segment())
                .wrapping_add(instruction.ip_rel_memory_address()));
        }

        let mut address = self
            .segment_base(instruction.memory_segment())
            .wrapping_add(instruction.memory_displacement64());
        let base = instruction.memory_base();
        if base != Register::None {
            let base_value = self.registers.read(base)?;
            address = address.wrapping_add(base_value);
        }

        let index = instruction.memory_index();
        if index != Register::None {
            let scale = u64::from(instruction.memory_index_scale());
            address = address.wrapping_add(self.registers.read(index)?.wrapping_mul(scale));
        }
        Ok(address)
    }

    fn segment_base(&self, segment: Register) -> u64 {
        match segment {
            Register::FS => self.registers.fs_base,
            Register::GS => self.registers.gs_base,
            _ => 0,
        }
    }

    fn branch_target(&self, instruction: &Instruction, op_index: u32) -> Result<u64, CpuError> {
        match instruction.op_kind(op_index) {
            OpKind::NearBranch16 => Ok(u64::from(instruction.near_branch16())),
            OpKind::NearBranch32 => Ok(u64::from(instruction.near_branch32())),
            OpKind::NearBranch64 => Ok(instruction.near_branch64()),
            OpKind::Register | OpKind::Memory => self.read_operand(instruction, op_index, 64),
            _ => Err(CpuError::UnsupportedOperand {
                ip: instruction.ip(),
                instruction: format_instruction(instruction),
            }),
        }
    }

    fn push_u64(&mut self, value: u64) -> Result<(), CpuError> {
        self.registers.rsp = self.registers.rsp.wrapping_sub(8);
        self.memory.write_u64(self.registers.rsp, value)?;
        Ok(())
    }

    fn pop_u64(&mut self) -> Result<u64, CpuError> {
        let value = self.memory.read_u64(self.registers.rsp)?;
        self.registers.rsp = self.registers.rsp.wrapping_add(8);
        Ok(value)
    }

    fn condition_passed(&self, mnemonic: Mnemonic) -> Result<bool, CpuError> {
        let cf = self.registers.flag(FLAG_CF);
        let zf = self.registers.flag(FLAG_ZF);
        let sf = self.registers.flag(FLAG_SF);
        let of = self.registers.flag(FLAG_OF);
        let pf = self.registers.flag(FLAG_PF);

        let passed = match mnemonic {
            Mnemonic::Jo => of,
            Mnemonic::Cmovo => of,
            Mnemonic::Seto => of,
            Mnemonic::Jno => !of,
            Mnemonic::Cmovno => !of,
            Mnemonic::Setno => !of,
            Mnemonic::Jb => cf,
            Mnemonic::Cmovb => cf,
            Mnemonic::Setb => cf,
            Mnemonic::Jae => !cf,
            Mnemonic::Cmovae => !cf,
            Mnemonic::Setae => !cf,
            Mnemonic::Je => zf,
            Mnemonic::Cmove => zf,
            Mnemonic::Sete => zf,
            Mnemonic::Jne => !zf,
            Mnemonic::Cmovne => !zf,
            Mnemonic::Setne => !zf,
            Mnemonic::Jbe => cf || zf,
            Mnemonic::Cmovbe => cf || zf,
            Mnemonic::Setbe => cf || zf,
            Mnemonic::Ja => !cf && !zf,
            Mnemonic::Cmova => !cf && !zf,
            Mnemonic::Seta => !cf && !zf,
            Mnemonic::Js => sf,
            Mnemonic::Cmovs => sf,
            Mnemonic::Sets => sf,
            Mnemonic::Jns => !sf,
            Mnemonic::Cmovns => !sf,
            Mnemonic::Setns => !sf,
            Mnemonic::Jp => pf,
            Mnemonic::Cmovp => pf,
            Mnemonic::Setp => pf,
            Mnemonic::Jnp => !pf,
            Mnemonic::Cmovnp => !pf,
            Mnemonic::Setnp => !pf,
            Mnemonic::Jl => sf != of,
            Mnemonic::Cmovl => sf != of,
            Mnemonic::Setl => sf != of,
            Mnemonic::Jge => sf == of,
            Mnemonic::Cmovge => sf == of,
            Mnemonic::Setge => sf == of,
            Mnemonic::Jle => zf || (sf != of),
            Mnemonic::Cmovle => zf || (sf != of),
            Mnemonic::Setle => zf || (sf != of),
            Mnemonic::Jg => !zf && (sf == of),
            Mnemonic::Cmovg => !zf && (sf == of),
            Mnemonic::Setg => !zf && (sf == of),
            _ => {
                return Err(CpuError::UnsupportedOperand {
                    ip: self.registers.rip,
                    instruction: format!("{mnemonic:?}"),
                });
            }
        };
        Ok(passed)
    }

    fn set_add_flags(&mut self, left: u64, right: u64, result: u64, width: u32) {
        let mask = mask(width);
        let sign = sign_bit(width);
        let left = left & mask;
        let right = right & mask;
        let result = result & mask;
        self.registers.set_flag(FLAG_CF, result < left);
        self.registers
            .set_flag(FLAG_OF, ((left ^ result) & (right ^ result) & sign) != 0);
        self.set_common_flags(result, width);
    }

    fn set_sub_flags(&mut self, left: u64, right: u64, result: u64, width: u32) {
        let mask = mask(width);
        let sign = sign_bit(width);
        let left = left & mask;
        let right = right & mask;
        let result = result & mask;
        self.registers.set_flag(FLAG_CF, left < right);
        self.registers
            .set_flag(FLAG_OF, ((left ^ right) & (left ^ result) & sign) != 0);
        self.set_common_flags(result, width);
    }

    fn set_logic_flags(&mut self, result: u64, width: u32) {
        self.registers.set_flag(FLAG_CF, false);
        self.registers.set_flag(FLAG_OF, false);
        self.set_common_flags(result, width);
    }

    fn set_common_flags(&mut self, result: u64, width: u32) {
        let masked = result & mask(width);
        self.registers.set_flag(FLAG_ZF, masked == 0);
        self.registers
            .set_flag(FLAG_SF, (masked & sign_bit(width)) != 0);
        self.registers
            .set_flag(FLAG_PF, (masked as u8).count_ones() % 2 == 0);
    }
}

#[derive(Debug, Clone, Copy)]
enum BinaryOp {
    Add,
    Sub,
    Adc,
    Sbb,
    Xor,
    And,
    Or,
}

#[derive(Debug, Clone, Copy)]
enum UnaryOp {
    Neg,
    Not,
    Inc,
    Dec,
}

#[derive(Debug, Clone, Copy)]
enum ShiftOp {
    Shl,
    Shr,
    Sar,
}

enum DoubleShiftOp {
    Shld,
    Shrd,
}

enum BitScanOp {
    Forward,
    Reverse,
}

#[derive(Debug, Clone, Copy)]
enum XmmBinaryOp {
    Xor,
    Or,
    And,
}

fn is_jcc(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jb
            | Mnemonic::Jae
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jl
            | Mnemonic::Jge
            | Mnemonic::Jle
            | Mnemonic::Jg
    )
}

fn is_setcc(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Seto
            | Mnemonic::Setno
            | Mnemonic::Setb
            | Mnemonic::Setae
            | Mnemonic::Sete
            | Mnemonic::Setne
            | Mnemonic::Setbe
            | Mnemonic::Seta
            | Mnemonic::Sets
            | Mnemonic::Setns
            | Mnemonic::Setp
            | Mnemonic::Setnp
            | Mnemonic::Setl
            | Mnemonic::Setge
            | Mnemonic::Setle
            | Mnemonic::Setg
    )
}

fn is_cmovcc(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Cmovo
            | Mnemonic::Cmovno
            | Mnemonic::Cmovb
            | Mnemonic::Cmovae
            | Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmovbe
            | Mnemonic::Cmova
            | Mnemonic::Cmovs
            | Mnemonic::Cmovns
            | Mnemonic::Cmovp
            | Mnemonic::Cmovnp
            | Mnemonic::Cmovl
            | Mnemonic::Cmovge
            | Mnemonic::Cmovle
            | Mnemonic::Cmovg
    )
}

fn instruction_kind(instruction: &Instruction) -> IrInstructionKind {
    match instruction.mnemonic() {
        Mnemonic::Syscall => IrInstructionKind::Syscall,
        Mnemonic::Jmp => IrInstructionKind::Branch,
        Mnemonic::Call => IrInstructionKind::Call,
        Mnemonic::Ret => IrInstructionKind::Return,
        mnemonic if is_jcc(mnemonic) => IrInstructionKind::Branch,
        _ => IrInstructionKind::Compute,
    }
}

fn block_terminator(kind: IrInstructionKind) -> BlockTerminator {
    match kind {
        IrInstructionKind::Compute => BlockTerminator::FallThrough,
        IrInstructionKind::Branch => BlockTerminator::Branch,
        IrInstructionKind::Call => BlockTerminator::Call,
        IrInstructionKind::Return => BlockTerminator::Return,
        IrInstructionKind::Syscall => BlockTerminator::Syscall,
    }
}

fn xmm_index(register: Register) -> Option<usize> {
    match register {
        Register::XMM0 => Some(0),
        Register::XMM1 => Some(1),
        Register::XMM2 => Some(2),
        Register::XMM3 => Some(3),
        Register::XMM4 => Some(4),
        Register::XMM5 => Some(5),
        Register::XMM6 => Some(6),
        Register::XMM7 => Some(7),
        Register::XMM8 => Some(8),
        Register::XMM9 => Some(9),
        Register::XMM10 => Some(10),
        Register::XMM11 => Some(11),
        Register::XMM12 => Some(12),
        Register::XMM13 => Some(13),
        Register::XMM14 => Some(14),
        Register::XMM15 => Some(15),
        _ => None,
    }
}

fn memory_size(instruction: &Instruction, fallback_width: u32) -> Result<usize, CpuError> {
    let size = instruction.memory_size().size();
    if size != 0 {
        return Ok(size);
    }
    if fallback_width == 0 || fallback_width > 64 {
        return Err(CpuError::UnsupportedOperand {
            ip: instruction.ip(),
            instruction: format_instruction(instruction),
        });
    }
    Ok((fallback_width / 8) as usize)
}

fn little_endian_to_u64(bytes: &[u8]) -> u64 {
    let mut value = 0;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    value
}

fn u64_to_little_endian(value: u64, size: usize) -> Vec<u8> {
    value.to_le_bytes()[..size].to_vec()
}

fn sign_extend(value: u64, from_width: u32) -> u64 {
    let sign = 1u64 << (from_width - 1);
    let mask = mask(from_width);
    let value = value & mask;
    if value & sign != 0 {
        value | !mask
    } else {
        value
    }
}

fn mask(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

fn sign_bit(width: u32) -> u64 {
    1u64 << (width - 1)
}

fn signed_min(width: u32) -> i128 {
    -(1i128 << (width - 1))
}

fn signed_max(width: u32) -> i128 {
    (1i128 << (width - 1)) - 1
}

fn format_instruction(instruction: &Instruction) -> String {
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    formatter.format(instruction, &mut output);
    output
}

fn split_instruction(text: &str) -> (String, Vec<String>) {
    let mut parts = text.splitn(2, ' ');
    let mnemonic = parts.next().unwrap_or_default().to_string();
    let operands = parts
        .next()
        .map(|operands| {
            operands
                .split(',')
                .map(str::trim)
                .filter(|operand| !operand.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    (mnemonic, operands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruxeon_core::MemoryPermission;

    const CODE: u64 = 0x1000;
    const STACK: u64 = 0x8000;

    fn interpreter(code: &[u8]) -> Interpreter {
        let mut memory = GuestMemory::new();
        memory
            .map_region(
                CODE,
                0x1000,
                MemoryPermission::READ | MemoryPermission::EXECUTE,
                Some("code".to_string()),
            )
            .unwrap();
        memory.load_bytes(CODE, code).unwrap();
        memory
            .map_region(
                STACK,
                0x1000,
                MemoryPermission::READ | MemoryPermission::WRITE,
                Some("stack".to_string()),
            )
            .unwrap();
        let registers = Registers {
            rip: CODE,
            rsp: STACK + 0x800,
            ..Registers::default()
        };
        Interpreter::new(memory, registers)
    }

    #[test]
    fn executes_integer_ops_until_exit_syscall() {
        let mut cpu = interpreter(&[
            0x48, 0xc7, 0xc0, 0x28, 0x00, 0x00, 0x00, // mov rax, 40
            0x48, 0x83, 0xc0, 0x02, // add rax, 2
            0x48, 0x83, 0xe8, 0x02, // sub rax, 2
            0x48, 0x31, 0xff, // xor rdi, rdi
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
            0x0f, 0x05, // syscall
        ]);

        assert_eq!(cpu.run(16).unwrap(), RunOutcome::Exited(0));
        assert_eq!(cpu.registers().rax, 60);
    }

    #[test]
    fn executes_memory_operands_with_sib() {
        let mut cpu = interpreter(&[
            0x48, 0xb8, 0xef, 0xbe, 0xfe, 0xca, 0xce, 0xfa, 0xed,
            0xfe, // mov rax, 0xfeedfacecafebeef
            0x48, 0x89, 0x44, 0x24, 0xf8, // mov [rsp-8], rax
            0x48, 0x8b, 0x5c, 0x24, 0xf8, // mov rbx, [rsp-8]
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
            0x31, 0xff, // xor edi, edi
            0x0f, 0x05, // syscall
        ]);

        assert_eq!(cpu.run(16).unwrap(), RunOutcome::Exited(0));
        assert_eq!(cpu.registers().rbx, 0xfeed_face_cafe_beef);
    }

    #[test]
    fn executes_call_ret_and_conditional_branch() {
        let mut cpu = interpreter(&[
            0xe8, 0x12, 0x00, 0x00, 0x00, // call function
            0x48, 0x83, 0xf8, 0x07, // cmp rax, 7
            0x74, 0x05, // je exit
            0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
            0x0f, 0x05, // syscall
            0x48, 0xc7, 0xc0, 0x07, 0x00, 0x00, 0x00, // mov rax, 7
            0xc3, // ret
        ]);

        assert_eq!(cpu.run(32).unwrap(), RunOutcome::Exited(0));
    }

    #[test]
    fn records_trace() {
        let mut cpu = interpreter(&[
            0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
            0x31, 0xff, // xor edi, edi
            0x0f, 0x05, // syscall
        ]);
        cpu.set_trace_enabled(true);

        assert_eq!(cpu.run(8).unwrap(), RunOutcome::Exited(0));
        assert_eq!(cpu.trace().len(), 3);
        assert!(cpu.trace()[0].instruction.contains("mov"));
    }

    #[test]
    fn cached_blocks_are_reused_by_rip() {
        let mut cpu = interpreter(&[
            0x90, // nop
            0xeb, 0xfd, // jmp 0x1000
        ]);

        assert_eq!(cpu.step_block().unwrap(), StepOutcome::Continue);
        assert_eq!(cpu.step_block().unwrap(), StepOutcome::Continue);

        let stats = cpu.cache_stats();
        assert_eq!(stats.blocks, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 1);
    }

    #[test]
    fn writes_to_executable_memory_invalidate_cached_blocks() {
        let mut memory = GuestMemory::new();
        memory
            .map_region(
                CODE,
                0x1000,
                MemoryPermission::READ | MemoryPermission::WRITE | MemoryPermission::EXECUTE,
                Some("rwx-code".to_string()),
            )
            .unwrap();
        memory
            .load_bytes(
                CODE,
                &[
                    0xc6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x90, // mov byte [rip], 0x90
                    0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
                    0x31, 0xff, // xor edi, edi
                    0x0f, 0x05, // syscall
                ],
            )
            .unwrap();
        memory
            .map_region(
                STACK,
                0x1000,
                MemoryPermission::READ | MemoryPermission::WRITE,
                Some("stack".to_string()),
            )
            .unwrap();
        let registers = Registers {
            rip: CODE,
            rsp: STACK + 0x800,
            ..Registers::default()
        };
        let mut cpu = Interpreter::new(memory, registers);

        assert_eq!(cpu.run(4).unwrap(), RunOutcome::Exited(0));
        assert_eq!(cpu.cache_stats().invalidations, 1);
    }
}
