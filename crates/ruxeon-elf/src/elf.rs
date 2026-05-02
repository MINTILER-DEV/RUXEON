use thiserror::Error;

pub const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EM_X86_64: u16 = 62;
pub const EV_CURRENT: u32 = 1;
pub const ET_DYN: u16 = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ElfError {
    #[error("input is too small to contain an ELF header")]
    TooSmall,
    #[error("invalid ELF magic")]
    BadMagic,
    #[error("unsupported ELF class {0}")]
    UnsupportedClass(u8),
    #[error("unsupported ELF data encoding {0}")]
    UnsupportedEndian(u8),
    #[error("unsupported ELF machine {0}")]
    UnsupportedMachine(u16),
    #[error("unsupported ELF version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid ELF header size {0}")]
    InvalidHeaderSize(u16),
    #[error("invalid program header entry size {0}")]
    InvalidProgramHeaderSize(u16),
    #[error("program header table is out of bounds")]
    ProgramHeadersOutOfBounds,
    #[error("program segment is out of bounds")]
    SegmentOutOfBounds,
    #[error("PT_LOAD segment has memsz smaller than filesz")]
    InvalidLoadSegment,
    #[error("dynamic section is out of bounds")]
    DynamicOutOfBounds,
    #[error("interpreter path is not valid UTF-8")]
    InvalidInterpreter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfHeader {
    pub file_type: u16,
    pub machine: u16,
    pub entry: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramHeaderType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Phdr,
    Tls,
    GnuStack,
    Other(u32),
}

impl From<u32> for ProgramHeaderType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interp,
            4 => Self::Note,
            6 => Self::Phdr,
            7 => Self::Tls,
            0x6474_e551 => Self::GnuStack,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeaderFlags {
    bits: u32,
}

impl ProgramHeaderFlags {
    pub const EXECUTE: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const READ: u32 = 4;

    pub fn new(bits: u32) -> Self {
        Self { bits }
    }

    pub fn bits(self) -> u32 {
        self.bits
    }

    pub fn readable(self) -> bool {
        self.bits & Self::READ != 0
    }

    pub fn writable(self) -> bool {
        self.bits & Self::WRITE != 0
    }

    pub fn executable(self) -> bool {
        self.bits & Self::EXECUTE != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramHeader {
    pub kind: ProgramHeaderType,
    pub flags: ProgramHeaderFlags,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub align: u64,
}

impl ProgramHeader {
    pub fn is_load(&self) -> bool {
        self.kind == ProgramHeaderType::Load
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfImage {
    bytes: Vec<u8>,
    header: ElfHeader,
    program_headers: Vec<ProgramHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicTag {
    Null,
    Needed,
    PltRelSize,
    PltGot,
    Hash,
    StrTab,
    SymTab,
    Rela,
    RelaSize,
    RelaEnt,
    StrSize,
    SymEnt,
    Init,
    Fini,
    SoName,
    RPath,
    Symbolic,
    Rel,
    RelSize,
    RelEnt,
    PltRel,
    Debug,
    TextRel,
    JmpRel,
    BindNow,
    InitArray,
    FiniArray,
    RunPath,
    Flags,
    GnuHash,
    Other(i64),
}

impl From<i64> for DynamicTag {
    fn from(value: i64) -> Self {
        match value {
            0 => Self::Null,
            1 => Self::Needed,
            2 => Self::PltRelSize,
            3 => Self::PltGot,
            4 => Self::Hash,
            5 => Self::StrTab,
            6 => Self::SymTab,
            7 => Self::Rela,
            8 => Self::RelaSize,
            9 => Self::RelaEnt,
            10 => Self::StrSize,
            11 => Self::SymEnt,
            12 => Self::Init,
            13 => Self::Fini,
            14 => Self::SoName,
            15 => Self::RPath,
            16 => Self::Symbolic,
            17 => Self::Rel,
            18 => Self::RelSize,
            19 => Self::RelEnt,
            20 => Self::PltRel,
            21 => Self::Debug,
            22 => Self::TextRel,
            23 => Self::JmpRel,
            24 => Self::BindNow,
            25 => Self::InitArray,
            26 => Self::FiniArray,
            29 => Self::RunPath,
            30 => Self::Flags,
            0x6fff_fef5 => Self::GnuHash,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub value: u64,
}

impl ElfImage {
    pub fn parse(bytes: impl Into<Vec<u8>>) -> Result<Self, ElfError> {
        let bytes = bytes.into();
        if bytes.len() < 64 {
            return Err(ElfError::TooSmall);
        }
        if &bytes[0..4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }
        if bytes[4] != ELFCLASS64 {
            return Err(ElfError::UnsupportedClass(bytes[4]));
        }
        if bytes[5] != ELFDATA2LSB {
            return Err(ElfError::UnsupportedEndian(bytes[5]));
        }

        let file_type = read_u16(&bytes, 16)?;
        let machine = read_u16(&bytes, 18)?;
        if machine != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine(machine));
        }
        let version = read_u32(&bytes, 20)?;
        if version != EV_CURRENT {
            return Err(ElfError::UnsupportedVersion(version));
        }

        let header = ElfHeader {
            file_type,
            machine,
            entry: read_u64(&bytes, 24)?,
            program_header_offset: read_u64(&bytes, 32)?,
            section_header_offset: read_u64(&bytes, 40)?,
            flags: read_u32(&bytes, 48)?,
            header_size: read_u16(&bytes, 52)?,
            program_header_entry_size: read_u16(&bytes, 54)?,
            program_header_count: read_u16(&bytes, 56)?,
        };

        if header.header_size < 64 {
            return Err(ElfError::InvalidHeaderSize(header.header_size));
        }
        if header.program_header_entry_size < 56 {
            return Err(ElfError::InvalidProgramHeaderSize(
                header.program_header_entry_size,
            ));
        }

        let phoff = usize::try_from(header.program_header_offset)
            .map_err(|_| ElfError::ProgramHeadersOutOfBounds)?;
        let phentsize = usize::from(header.program_header_entry_size);
        let phnum = usize::from(header.program_header_count);
        let phtable_size = phentsize
            .checked_mul(phnum)
            .ok_or(ElfError::ProgramHeadersOutOfBounds)?;
        let phtable_end = phoff
            .checked_add(phtable_size)
            .ok_or(ElfError::ProgramHeadersOutOfBounds)?;
        if phtable_end > bytes.len() {
            return Err(ElfError::ProgramHeadersOutOfBounds);
        }

        let mut program_headers = Vec::with_capacity(phnum);
        for index in 0..phnum {
            let offset = phoff + index * phentsize;
            let header = ProgramHeader {
                kind: ProgramHeaderType::from(read_u32(&bytes, offset)?),
                flags: ProgramHeaderFlags::new(read_u32(&bytes, offset + 4)?),
                offset: read_u64(&bytes, offset + 8)?,
                virtual_address: read_u64(&bytes, offset + 16)?,
                physical_address: read_u64(&bytes, offset + 24)?,
                file_size: read_u64(&bytes, offset + 32)?,
                memory_size: read_u64(&bytes, offset + 40)?,
                align: read_u64(&bytes, offset + 48)?,
            };
            if header.is_load() {
                validate_load_segment(&bytes, &header)?;
            }
            program_headers.push(header);
        }

        Ok(Self {
            bytes,
            header,
            program_headers,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn header(&self) -> &ElfHeader {
        &self.header
    }

    pub fn program_headers(&self) -> &[ProgramHeader] {
        &self.program_headers
    }

    pub fn entry(&self) -> u64 {
        self.header.entry
    }

    pub fn is_position_independent(&self) -> bool {
        self.header.file_type == ET_DYN
    }

    pub fn interpreter_path(&self) -> Result<Option<String>, ElfError> {
        let Some(header) = self
            .program_headers
            .iter()
            .find(|header| header.kind == ProgramHeaderType::Interp)
        else {
            return Ok(None);
        };
        let data = segment_bytes(&self.bytes, header)?;
        let nul = data
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(data.len());
        let path = std::str::from_utf8(&data[..nul]).map_err(|_| ElfError::InvalidInterpreter)?;
        Ok(Some(path.to_string()))
    }

    pub fn dynamic_entries(&self) -> Result<Vec<DynamicEntry>, ElfError> {
        let Some(header) = self
            .program_headers
            .iter()
            .find(|header| header.kind == ProgramHeaderType::Dynamic)
        else {
            return Ok(Vec::new());
        };
        let data = segment_bytes(&self.bytes, header)?;
        if data.len() % 16 != 0 {
            return Err(ElfError::DynamicOutOfBounds);
        }
        let mut entries = Vec::new();
        for chunk in data.chunks_exact(16) {
            let tag = i64::from_le_bytes(chunk[0..8].try_into().expect("dynamic tag length"));
            let value = u64::from_le_bytes(chunk[8..16].try_into().expect("dynamic value length"));
            let tag = DynamicTag::from(tag);
            entries.push(DynamicEntry { tag, value });
            if tag == DynamicTag::Null {
                break;
            }
        }
        Ok(entries)
    }
}

fn validate_load_segment(bytes: &[u8], header: &ProgramHeader) -> Result<(), ElfError> {
    if header.memory_size < header.file_size {
        return Err(ElfError::InvalidLoadSegment);
    }
    let start = usize::try_from(header.offset).map_err(|_| ElfError::SegmentOutOfBounds)?;
    let file_size = usize::try_from(header.file_size).map_err(|_| ElfError::SegmentOutOfBounds)?;
    let end = start
        .checked_add(file_size)
        .ok_or(ElfError::SegmentOutOfBounds)?;
    if end > bytes.len() {
        return Err(ElfError::SegmentOutOfBounds);
    }
    Ok(())
}

fn segment_bytes<'a>(bytes: &'a [u8], header: &ProgramHeader) -> Result<&'a [u8], ElfError> {
    let start = usize::try_from(header.offset).map_err(|_| ElfError::SegmentOutOfBounds)?;
    let file_size = usize::try_from(header.file_size).map_err(|_| ElfError::SegmentOutOfBounds)?;
    let end = start
        .checked_add(file_size)
        .ok_or(ElfError::SegmentOutOfBounds)?;
    bytes.get(start..end).ok_or(ElfError::SegmentOutOfBounds)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ElfError> {
    let end = offset.checked_add(2).ok_or(ElfError::TooSmall)?;
    let bytes = bytes.get(offset..end).ok_or(ElfError::TooSmall)?;
    Ok(u16::from_le_bytes(bytes.try_into().expect("u16 length")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ElfError> {
    let end = offset.checked_add(4).ok_or(ElfError::TooSmall)?;
    let bytes = bytes.get(offset..end).ok_or(ElfError::TooSmall)?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("u32 length")))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ElfError> {
    let end = offset.checked_add(8).ok_or(ElfError::TooSmall)?;
    let bytes = bytes.get(offset..end).ok_or(ElfError::TooSmall)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("u64 length")))
}

#[cfg(test)]
pub(crate) fn tiny_elf_fixture() -> Vec<u8> {
    let mut bytes = vec![0; 0x80];
    bytes[0..4].copy_from_slice(ELF_MAGIC);
    bytes[4] = ELFCLASS64;
    bytes[5] = ELFDATA2LSB;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    bytes[20..24].copy_from_slice(&EV_CURRENT.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    let ph = 64;
    bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&0x80u64.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x80u64.to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x78] = 0x0f;
    bytes[0x79] = 0x05;
    bytes
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn parses_minimal_elf_header_and_program_header() {
        let bytes = tiny_elf_fixture();
        let image = ElfImage::parse(bytes).unwrap();

        assert_eq!(image.entry(), 0x400078);
        assert_eq!(image.program_headers().len(), 1);
        assert_eq!(image.program_headers()[0].kind, ProgramHeaderType::Load);
        assert_eq!(image.program_headers()[0].virtual_address, 0x400000);
    }

    #[test]
    fn rejects_non_x86_64_elf() {
        let mut bytes = tiny_elf_fixture();
        bytes[18..20].copy_from_slice(&3u16.to_le_bytes());

        assert_eq!(
            ElfImage::parse(bytes).unwrap_err(),
            ElfError::UnsupportedMachine(3)
        );
    }

    #[test]
    fn parses_interp_and_dynamic_entries() {
        let image = ElfImage::parse(dynamic_elf_fixture()).unwrap();

        assert_eq!(
            image.interpreter_path().unwrap(),
            Some("/lib64/ld-linux-x86-64.so.2".to_string())
        );
        assert_eq!(image.dynamic_entries().unwrap()[0].tag, DynamicTag::Needed);
    }

    pub(crate) fn dynamic_elf_fixture() -> Vec<u8> {
        let mut bytes = vec![0; 0x200];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&EV_CURRENT.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x180u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&3u16.to_le_bytes());

        write_program_header(&mut bytes, 64, 1, 5, 0, 0, 0x200, 0x200);
        write_program_header(&mut bytes, 120, 3, 4, 0x150, 0x150, 28, 28);
        write_program_header(&mut bytes, 176, 2, 4, 0x170, 0x170, 32, 32);

        bytes[0x150..0x16c].copy_from_slice(b"/lib64/ld-linux-x86-64.so.2\0");
        bytes[0x170..0x178].copy_from_slice(&1i64.to_le_bytes());
        bytes[0x178..0x180].copy_from_slice(&0x20u64.to_le_bytes());
        bytes[0x180] = 0x0f;
        bytes[0x181] = 0x05;
        bytes
    }

    fn write_program_header(
        bytes: &mut [u8],
        offset: usize,
        kind: u32,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
    ) {
        bytes[offset..offset + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&flags.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&file_offset.to_le_bytes());
        bytes[offset + 16..offset + 24].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[offset + 24..offset + 32].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[offset + 32..offset + 40].copy_from_slice(&file_size.to_le_bytes());
        bytes[offset + 40..offset + 48].copy_from_slice(&memory_size.to_le_bytes());
        bytes[offset + 48..offset + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    }
}
