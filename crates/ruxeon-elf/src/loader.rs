use crate::{ElfError, ElfImage, ProgramHeader, ProgramHeaderType};
use ruxeon_core::{GuestMemory, GuestMemoryError, MemoryPermission, PAGE_SIZE};
use thiserror::Error;

const DEFAULT_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
const DEFAULT_STACK_SIZE: u64 = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error(transparent)]
    Elf(#[from] ElfError),
    #[error(transparent)]
    Memory(#[from] GuestMemoryError),
    #[error("ELF image has no loadable segments")]
    NoLoadSegments,
    #[error("program header address could not be derived")]
    MissingProgramHeaderAddress,
    #[error("initial stack does not have enough space")]
    StackOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderConfig {
    pub stack_top: u64,
    pub stack_size: u64,
    pub page_size: u64,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            stack_top: DEFAULT_STACK_TOP,
            stack_size: DEFAULT_STACK_SIZE,
            page_size: PAGE_SIZE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AuxType {
    Null = 0,
    Phdr = 3,
    Phent = 4,
    Phnum = 5,
    Pagesz = 6,
    Base = 7,
    Entry = 9,
    Uid = 11,
    EUid = 12,
    Gid = 13,
    EGid = 14,
    Secure = 23,
    Random = 25,
    ExecFn = 31,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxEntry {
    pub kind: AuxType,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct LoadedProgram {
    pub image: ElfImage,
    pub memory: GuestMemory,
    pub entry: u64,
    pub stack_pointer: u64,
    pub auxv: Vec<AuxEntry>,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
}

impl LoadedProgram {
    pub fn load(
        bytes: impl Into<Vec<u8>>,
        argv: &[String],
        envp: &[String],
    ) -> Result<Self, LoaderError> {
        Self::load_with_config(bytes, argv, envp, LoaderConfig::default())
    }

    pub fn load_with_config(
        bytes: impl Into<Vec<u8>>,
        argv: &[String],
        envp: &[String],
        config: LoaderConfig,
    ) -> Result<Self, LoaderError> {
        let image = ElfImage::parse(bytes)?;
        let mut memory = GuestMemory::new();
        let mut has_load = false;

        for header in image
            .program_headers()
            .iter()
            .filter(|header| header.is_load())
        {
            has_load = true;
            load_segment(&mut memory, &image, header, config.page_size)?;
        }

        if !has_load {
            return Err(LoaderError::NoLoadSegments);
        }

        let phdr =
            program_header_guest_address(&image).ok_or(LoaderError::MissingProgramHeaderAddress)?;
        let stack_base = config
            .stack_top
            .checked_sub(config.stack_size)
            .ok_or(LoaderError::StackOverflow)?;
        memory.map_region(
            stack_base,
            config.stack_size,
            MemoryPermission::READ | MemoryPermission::WRITE,
            Some("[stack]".to_string()),
        )?;

        let mut stack = InitialStack::new(config.stack_top, stack_base);
        let stack_result = stack.build(
            &mut memory,
            argv,
            envp,
            StackAuxInput {
                phdr,
                phent: u64::from(image.header().program_header_entry_size),
                phnum: u64::from(image.header().program_header_count),
                entry: image.entry(),
                page_size: config.page_size,
            },
        )?;

        Ok(Self {
            entry: image.entry(),
            image,
            memory,
            stack_pointer: stack_result.stack_pointer,
            auxv: stack_result.auxv,
            argv: argv.to_vec(),
            envp: envp.to_vec(),
        })
    }
}

fn load_segment(
    memory: &mut GuestMemory,
    image: &ElfImage,
    header: &ProgramHeader,
    page_size: u64,
) -> Result<(), LoaderError> {
    let map_start = align_down(header.virtual_address, page_size);
    let segment_end = header
        .virtual_address
        .checked_add(header.memory_size)
        .ok_or(GuestMemoryError::AddressOverflow {
            base: header.virtual_address,
            size: header.memory_size,
        })?;
    let map_end = align_up(segment_end, page_size);
    let map_size = map_end - map_start;
    let data_offset = header.virtual_address - map_start;
    let file_start = usize::try_from(header.offset).map_err(|_| ElfError::SegmentOutOfBounds)?;
    let file_size = usize::try_from(header.file_size).map_err(|_| ElfError::SegmentOutOfBounds)?;
    let file_end = file_start + file_size;
    let data = &image.bytes()[file_start..file_end];

    memory.map_with_data(
        map_start,
        map_size,
        permissions_from_header(header),
        data_offset,
        data,
        Some(format!("PT_LOAD {:#x}", header.virtual_address)),
    )?;
    Ok(())
}

fn permissions_from_header(header: &ProgramHeader) -> MemoryPermission {
    let mut permissions = MemoryPermission::empty();
    if header.flags.readable() {
        permissions |= MemoryPermission::READ;
    }
    if header.flags.writable() {
        permissions |= MemoryPermission::WRITE;
    }
    if header.flags.executable() {
        permissions |= MemoryPermission::EXECUTE;
    }
    permissions
}

fn program_header_guest_address(image: &ElfImage) -> Option<u64> {
    let phoff = image.header().program_header_offset;
    image
        .program_headers()
        .iter()
        .find(|header| {
            header.kind == ProgramHeaderType::Phdr
                || (header.is_load()
                    && phoff >= header.offset
                    && phoff < header.offset.saturating_add(header.file_size))
        })
        .map(|header| {
            if header.kind == ProgramHeaderType::Phdr {
                header.virtual_address
            } else {
                header.virtual_address + (phoff - header.offset)
            }
        })
}

#[derive(Debug, Clone, Copy)]
struct StackAuxInput {
    phdr: u64,
    phent: u64,
    phnum: u64,
    entry: u64,
    page_size: u64,
}

#[derive(Debug, Clone)]
struct StackBuildResult {
    stack_pointer: u64,
    auxv: Vec<AuxEntry>,
}

struct InitialStack {
    sp: u64,
    floor: u64,
}

impl InitialStack {
    fn new(top: u64, floor: u64) -> Self {
        Self { sp: top, floor }
    }

    fn build(
        &mut self,
        memory: &mut GuestMemory,
        argv: &[String],
        envp: &[String],
        input: StackAuxInput,
    ) -> Result<StackBuildResult, LoaderError> {
        let execfn = argv.first().cloned().unwrap_or_default();
        let execfn_ptr = self.push_c_string(memory, &execfn)?;
        let random_ptr = self.push_bytes(memory, &[0x52; 16])?;

        let mut env_ptrs = Vec::with_capacity(envp.len());
        for value in envp.iter().rev() {
            env_ptrs.push(self.push_c_string(memory, value)?);
        }
        env_ptrs.reverse();

        let mut argv_ptrs = Vec::with_capacity(argv.len());
        for value in argv.iter().rev() {
            argv_ptrs.push(self.push_c_string(memory, value)?);
        }
        argv_ptrs.reverse();

        self.align_down(16);

        let auxv = vec![
            AuxEntry {
                kind: AuxType::Phdr,
                value: input.phdr,
            },
            AuxEntry {
                kind: AuxType::Phent,
                value: input.phent,
            },
            AuxEntry {
                kind: AuxType::Phnum,
                value: input.phnum,
            },
            AuxEntry {
                kind: AuxType::Pagesz,
                value: input.page_size,
            },
            AuxEntry {
                kind: AuxType::Base,
                value: 0,
            },
            AuxEntry {
                kind: AuxType::Entry,
                value: input.entry,
            },
            AuxEntry {
                kind: AuxType::Uid,
                value: 0,
            },
            AuxEntry {
                kind: AuxType::EUid,
                value: 0,
            },
            AuxEntry {
                kind: AuxType::Gid,
                value: 0,
            },
            AuxEntry {
                kind: AuxType::EGid,
                value: 0,
            },
            AuxEntry {
                kind: AuxType::Secure,
                value: 0,
            },
            AuxEntry {
                kind: AuxType::Random,
                value: random_ptr,
            },
            AuxEntry {
                kind: AuxType::ExecFn,
                value: execfn_ptr,
            },
            AuxEntry {
                kind: AuxType::Null,
                value: 0,
            },
        ];

        for entry in auxv.iter().rev() {
            self.push_u64(memory, entry.value)?;
            self.push_u64(memory, entry.kind as u64)?;
        }
        self.push_u64(memory, 0)?;
        for ptr in env_ptrs.iter().rev() {
            self.push_u64(memory, *ptr)?;
        }
        self.push_u64(memory, 0)?;
        for ptr in argv_ptrs.iter().rev() {
            self.push_u64(memory, *ptr)?;
        }
        self.push_u64(memory, argv.len() as u64)?;

        Ok(StackBuildResult {
            stack_pointer: self.sp,
            auxv,
        })
    }

    fn push_c_string(&mut self, memory: &mut GuestMemory, value: &str) -> Result<u64, LoaderError> {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.push_bytes(memory, &bytes)
    }

    fn push_bytes(&mut self, memory: &mut GuestMemory, bytes: &[u8]) -> Result<u64, LoaderError> {
        let size = u64::try_from(bytes.len()).map_err(|_| LoaderError::StackOverflow)?;
        self.sp = self
            .sp
            .checked_sub(size)
            .ok_or(LoaderError::StackOverflow)?;
        if self.sp < self.floor {
            return Err(LoaderError::StackOverflow);
        }
        memory.write_bytes(self.sp, bytes)?;
        Ok(self.sp)
    }

    fn push_u64(&mut self, memory: &mut GuestMemory, value: u64) -> Result<(), LoaderError> {
        let bytes = value.to_le_bytes();
        self.push_bytes(memory, &bytes)?;
        Ok(())
    }

    fn align_down(&mut self, align: u64) {
        self.sp &= !(align - 1);
    }
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    align_down(value + align - 1, align)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_elf() -> Vec<u8> {
        crate::elf::tiny_elf_fixture()
    }

    #[test]
    fn loads_pt_load_segment_and_stack() {
        let argv = vec!["hello-static".to_string(), "world".to_string()];
        let envp = vec!["A=B".to_string()];
        let loaded = LoadedProgram::load(tiny_elf(), &argv, &envp).unwrap();

        assert_eq!(loaded.entry, 0x400078);
        assert!(loaded.memory.permissions_at(0x400078).unwrap().executable());
        assert_eq!(
            loaded.memory.fetch_bytes(0x400078, 2).unwrap(),
            [0x0f, 0x05]
        );
        assert_eq!(
            loaded.memory.read_u64(loaded.stack_pointer).unwrap(),
            argv.len() as u64
        );
        assert!(loaded
            .auxv
            .iter()
            .any(|entry| entry.kind == AuxType::Entry && entry.value == loaded.entry));
    }
}
