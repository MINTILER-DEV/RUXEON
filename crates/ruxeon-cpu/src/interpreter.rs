use crate::registers::{
    register_width, RegisterError, Registers, FLAG_CF, FLAG_OF, FLAG_PF, FLAG_SF, FLAG_ZF,
};
use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind,
    Register,
};
use ruxeon_core::{GuestMemory, GuestMemoryError};
use thiserror::Error;

const MAX_INSTRUCTION_LEN: usize = 15;

#[derive(Debug, Error)]
pub enum CpuError {
    #[error(transparent)]
    Memory(#[from] GuestMemoryError),
    #[error(transparent)]
    Register(#[from] RegisterError),
    #[error("invalid instruction at {0:#x}")]
    InvalidInstruction(u64),
    #[error("unsupported instruction at {ip:#x}: {instruction}")]
    UnsupportedInstruction { ip: u64, instruction: String },
    #[error("unsupported operand at {ip:#x}: {instruction}")]
    UnsupportedOperand { ip: u64, instruction: String },
    #[error("step limit must be greater than zero")]
    EmptyStepLimit,
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
    trace_enabled: bool,
    trace: Vec<TraceRecord>,
}

impl Interpreter {
    pub fn new(memory: GuestMemory, registers: Registers) -> Self {
        Self {
            memory,
            registers,
            trace_enabled: false,
            trace: Vec::new(),
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
    }

    pub fn set_trace_enabled(&mut self, enabled: bool) {
        self.trace_enabled = enabled;
    }

    pub fn trace(&self) -> &[TraceRecord] {
        &self.trace
    }

    pub fn step(&mut self) -> Result<StepOutcome, CpuError> {
        let ip = self.registers.rip;
        let instruction = self.decode(ip)?;
        if instruction.code() == Code::INVALID {
            return Err(CpuError::InvalidInstruction(ip));
        }

        let text = format_instruction(&instruction);
        let before = self.registers;
        let outcome = self.execute(&instruction, &text)?;
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

    pub fn run(&mut self, max_steps: u64) -> Result<RunOutcome, CpuError> {
        if max_steps == 0 {
            return Err(CpuError::EmptyStepLimit);
        }

        for _ in 0..max_steps {
            match self.step()? {
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

    fn execute(&mut self, instruction: &Instruction, text: &str) -> Result<StepOutcome, CpuError> {
        let ip = self.registers.rip;
        let next_ip = instruction.next_ip();
        let mut rip_written = false;
        let outcome = match instruction.mnemonic() {
            Mnemonic::Mov => {
                let width = self.destination_width(instruction, 0)?;
                let value = self.read_operand(instruction, 1, width)?;
                self.write_operand(instruction, 0, value, width)?;
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
            Mnemonic::Cmp => {
                let width = self.destination_width(instruction, 0)?;
                let left = self.read_operand(instruction, 0, width)?;
                let right = self.read_operand(instruction, 1, width)?;
                self.set_sub_flags(left, right, left.wrapping_sub(right), width);
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
                    ip,
                    instruction: text.to_string(),
                })
            }
        };

        if !rip_written {
            self.registers.rip = next_ip;
        }
        Ok(outcome)
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
                self.memory.write_bytes(address, &bytes)?;
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

    fn effective_address(&self, instruction: &Instruction) -> Result<u64, CpuError> {
        if instruction.is_ip_rel_memory_operand() {
            return Ok(instruction.ip_rel_memory_address());
        }

        let mut address = instruction.memory_displacement64();
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
            Mnemonic::Jno => !of,
            Mnemonic::Jb => cf,
            Mnemonic::Jae => !cf,
            Mnemonic::Je => zf,
            Mnemonic::Jne => !zf,
            Mnemonic::Jbe => cf || zf,
            Mnemonic::Ja => !cf && !zf,
            Mnemonic::Js => sf,
            Mnemonic::Jns => !sf,
            Mnemonic::Jp => pf,
            Mnemonic::Jnp => !pf,
            Mnemonic::Jl => sf != of,
            Mnemonic::Jge => sf == of,
            Mnemonic::Jle => zf || (sf != of),
            Mnemonic::Jg => !zf && (sf == of),
            _ => {
                return Err(CpuError::UnsupportedInstruction {
                    ip: self.registers.rip,
                    instruction: format!("{mnemonic:?}"),
                })
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
    Xor,
    And,
    Or,
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

fn format_instruction(instruction: &Instruction) -> String {
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    formatter.format(instruction, &mut output);
    output
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
}
