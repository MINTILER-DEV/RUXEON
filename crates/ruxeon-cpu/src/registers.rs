use iced_x86::Register;
use thiserror::Error;

pub const FLAG_CF: u64 = 1 << 0;
pub const FLAG_PF: u64 = 1 << 2;
pub const FLAG_ZF: u64 = 1 << 6;
pub const FLAG_SF: u64 = 1 << 7;
pub const FLAG_DF: u64 = 1 << 10;
pub const FLAG_OF: u64 = 1 << 11;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegisterError {
    #[error("unsupported register {0:?}")]
    Unsupported(Register),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub xmm: [u128; 16],
    pub fs_base: u64,
    pub gs_base: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl Default for Registers {
    fn default() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            xmm: [0; 16],
            fs_base: 0,
            gs_base: 0,
            rip: 0,
            rflags: 0x2,
        }
    }
}

impl Registers {
    pub fn read(&self, register: Register) -> Result<u64, RegisterError> {
        let value = match register {
            Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => self.rax,
            Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => self.rbx,
            Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => self.rcx,
            Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => self.rdx,
            Register::RSI | Register::ESI | Register::SI | Register::SIL => self.rsi,
            Register::RDI | Register::EDI | Register::DI | Register::DIL => self.rdi,
            Register::RBP | Register::EBP | Register::BP | Register::BPL => self.rbp,
            Register::RSP | Register::ESP | Register::SP | Register::SPL => self.rsp,
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => self.r8,
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => self.r9,
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => self.r10,
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => self.r11,
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => self.r12,
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => self.r13,
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => self.r14,
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => self.r15,
            Register::RIP | Register::EIP => self.rip,
            _ => return Err(RegisterError::Unsupported(register)),
        };
        Ok(extract_register_bits(register, value))
    }

    pub fn write(&mut self, register: Register, value: u64) -> Result<(), RegisterError> {
        match register {
            Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => {
                write_register_bits(&mut self.rax, register, value)
            }
            Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => {
                write_register_bits(&mut self.rbx, register, value)
            }
            Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => {
                write_register_bits(&mut self.rcx, register, value)
            }
            Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => {
                write_register_bits(&mut self.rdx, register, value)
            }
            Register::RSI | Register::ESI | Register::SI | Register::SIL => {
                write_register_bits(&mut self.rsi, register, value)
            }
            Register::RDI | Register::EDI | Register::DI | Register::DIL => {
                write_register_bits(&mut self.rdi, register, value)
            }
            Register::RBP | Register::EBP | Register::BP | Register::BPL => {
                write_register_bits(&mut self.rbp, register, value)
            }
            Register::RSP | Register::ESP | Register::SP | Register::SPL => {
                write_register_bits(&mut self.rsp, register, value)
            }
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => {
                write_register_bits(&mut self.r8, register, value)
            }
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => {
                write_register_bits(&mut self.r9, register, value)
            }
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => {
                write_register_bits(&mut self.r10, register, value)
            }
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => {
                write_register_bits(&mut self.r11, register, value)
            }
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => {
                write_register_bits(&mut self.r12, register, value)
            }
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => {
                write_register_bits(&mut self.r13, register, value)
            }
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => {
                write_register_bits(&mut self.r14, register, value)
            }
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => {
                write_register_bits(&mut self.r15, register, value)
            }
            Register::RIP | Register::EIP => {
                self.rip = value;
            }
            _ => return Err(RegisterError::Unsupported(register)),
        }
        Ok(())
    }

    pub fn flag(&self, flag: u64) -> bool {
        self.rflags & flag != 0
    }

    pub fn set_flag(&mut self, flag: u64, value: bool) {
        if value {
            self.rflags |= flag;
        } else {
            self.rflags &= !flag;
        }
        self.rflags |= 0x2;
    }
}

pub fn register_width(register: Register) -> Result<u32, RegisterError> {
    let width = match register {
        Register::AL
        | Register::AH
        | Register::BL
        | Register::BH
        | Register::CL
        | Register::CH
        | Register::DL
        | Register::DH
        | Register::SPL
        | Register::BPL
        | Register::SIL
        | Register::DIL
        | Register::R8L
        | Register::R9L
        | Register::R10L
        | Register::R11L
        | Register::R12L
        | Register::R13L
        | Register::R14L
        | Register::R15L => 8,
        Register::AX
        | Register::BX
        | Register::CX
        | Register::DX
        | Register::SI
        | Register::DI
        | Register::BP
        | Register::SP
        | Register::R8W
        | Register::R9W
        | Register::R10W
        | Register::R11W
        | Register::R12W
        | Register::R13W
        | Register::R14W
        | Register::R15W => 16,
        Register::EAX
        | Register::EBX
        | Register::ECX
        | Register::EDX
        | Register::ESI
        | Register::EDI
        | Register::EBP
        | Register::ESP
        | Register::R8D
        | Register::R9D
        | Register::R10D
        | Register::R11D
        | Register::R12D
        | Register::R13D
        | Register::R14D
        | Register::R15D
        | Register::EIP => 32,
        Register::RAX
        | Register::RBX
        | Register::RCX
        | Register::RDX
        | Register::RSI
        | Register::RDI
        | Register::RBP
        | Register::RSP
        | Register::R8
        | Register::R9
        | Register::R10
        | Register::R11
        | Register::R12
        | Register::R13
        | Register::R14
        | Register::R15
        | Register::RIP => 64,
        _ => return Err(RegisterError::Unsupported(register)),
    };
    Ok(width)
}

fn extract_register_bits(register: Register, value: u64) -> u64 {
    match register {
        Register::AH | Register::BH | Register::CH | Register::DH => (value >> 8) & 0xff,
        _ => {
            let width = register_width(register).unwrap_or(64);
            value & mask(width)
        }
    }
}

fn write_register_bits(slot: &mut u64, register: Register, value: u64) {
    match register_width(register).unwrap_or(64) {
        8 if matches!(
            register,
            Register::AH | Register::BH | Register::CH | Register::DH
        ) =>
        {
            *slot = (*slot & !0xff00) | ((value & 0xff) << 8);
        }
        8 => {
            *slot = (*slot & !0xff) | (value & 0xff);
        }
        16 => {
            *slot = (*slot & !0xffff) | (value & 0xffff);
        }
        32 => {
            *slot = value & 0xffff_ffff;
        }
        _ => {
            *slot = value;
        }
    }
}

fn mask(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}
