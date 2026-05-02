use bitflags::bitflags;
use std::ops::Range;
use thiserror::Error;

pub const PAGE_SIZE: u64 = 4096;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryPermission: u8 {
        const READ = 0b001;
        const WRITE = 0b010;
        const EXECUTE = 0b100;
    }
}

impl MemoryPermission {
    pub fn readable(self) -> bool {
        self.contains(Self::READ)
    }

    pub fn writable(self) -> bool {
        self.contains(Self::WRITE)
    }

    pub fn executable(self) -> bool {
        self.contains(Self::EXECUTE)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuestMemoryError {
    #[error("memory mapping at {base:#x} with size {size:#x} overlaps an existing mapping")]
    OverlappingMapping { base: u64, size: u64 },
    #[error("memory access at {addr:#x} with size {size:#x} is unmapped")]
    Unmapped { addr: u64, size: usize },
    #[error("memory access at {addr:#x} with size {size:#x} violates permissions {required:?}")]
    Permission {
        addr: u64,
        size: usize,
        required: MemoryPermission,
    },
    #[error("memory address overflow for base {base:#x} and size {size:#x}")]
    AddressOverflow { base: u64, size: u64 },
    #[error("memory mapping size must be non-zero")]
    EmptyMapping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    base: u64,
    size: u64,
    permissions: MemoryPermission,
    name: Option<String>,
    data: Vec<u8>,
}

impl MemoryRegion {
    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn end(&self) -> u64 {
        self.base + self.size
    }

    pub fn permissions(&self) -> MemoryPermission {
        self.permissions
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn range(&self) -> Range<u64> {
        self.base..self.end()
    }

    fn contains_range(&self, addr: u64, size: usize) -> bool {
        let Ok(size) = u64::try_from(size) else {
            return false;
        };
        let Some(end) = addr.checked_add(size) else {
            return false;
        };
        addr >= self.base && end <= self.end()
    }

    fn offset(&self, addr: u64) -> usize {
        usize::try_from(addr - self.base).expect("region offset fits usize")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryMap {
    regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    fn push(&mut self, region: MemoryRegion) {
        self.regions.push(region);
        self.regions.sort_by_key(|region| region.base);
    }

    fn find_index(&self, addr: u64, size: usize) -> Option<usize> {
        self.regions
            .iter()
            .position(|region| region.contains_range(addr, size))
    }

    fn overlaps(&self, base: u64, size: u64) -> bool {
        let end = base + size;
        self.regions
            .iter()
            .any(|region| ranges_overlap(base..end, region.range()))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestMemory {
    map: MemoryMap,
}

impl GuestMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn map(&self) -> &MemoryMap {
        &self.map
    }

    pub fn map_region(
        &mut self,
        base: u64,
        size: u64,
        permissions: MemoryPermission,
        name: impl Into<Option<String>>,
    ) -> Result<(), GuestMemoryError> {
        if size == 0 {
            return Err(GuestMemoryError::EmptyMapping);
        }
        base.checked_add(size)
            .ok_or(GuestMemoryError::AddressOverflow { base, size })?;
        if self.map.overlaps(base, size) {
            return Err(GuestMemoryError::OverlappingMapping { base, size });
        }

        let size_usize =
            usize::try_from(size).map_err(|_| GuestMemoryError::AddressOverflow { base, size })?;
        self.map.push(MemoryRegion {
            base,
            size,
            permissions,
            name: name.into(),
            data: vec![0; size_usize],
        });
        Ok(())
    }

    pub fn map_with_data(
        &mut self,
        base: u64,
        size: u64,
        permissions: MemoryPermission,
        data_offset: u64,
        data: &[u8],
        name: impl Into<Option<String>>,
    ) -> Result<(), GuestMemoryError> {
        self.map_region(base, size, permissions, name)?;
        self.load_bytes(base + data_offset, data)
    }

    pub fn protect(
        &mut self,
        base: u64,
        size: usize,
        permissions: MemoryPermission,
    ) -> Result<(), GuestMemoryError> {
        if size == 0 {
            return Ok(());
        }
        let index = self
            .map
            .find_index(base, size)
            .ok_or(GuestMemoryError::Unmapped { addr: base, size })?;
        let region = self.map.regions.remove(index);
        let protect_size = u64::try_from(size).map_err(|_| GuestMemoryError::AddressOverflow {
            base,
            size: u64::MAX,
        })?;
        let protect_end =
            base.checked_add(protect_size)
                .ok_or(GuestMemoryError::AddressOverflow {
                    base,
                    size: protect_size,
                })?;
        let before_size = base - region.base;
        let after_size = region.end() - protect_end;

        if before_size > 0 {
            let before_len = before_size as usize;
            self.map.push(MemoryRegion {
                base: region.base,
                size: before_size,
                permissions: region.permissions,
                name: region.name.clone(),
                data: region.data[..before_len].to_vec(),
            });
        }

        let protected_offset = before_size as usize;
        let protected_len = size;
        self.map.push(MemoryRegion {
            base,
            size: protect_size,
            permissions,
            name: region.name.clone(),
            data: region.data[protected_offset..protected_offset + protected_len].to_vec(),
        });

        if after_size > 0 {
            let after_offset = protected_offset + protected_len;
            self.map.push(MemoryRegion {
                base: protect_end,
                size: after_size,
                permissions: region.permissions,
                name: region.name,
                data: region.data[after_offset..].to_vec(),
            });
        }
        Ok(())
    }

    pub fn unmap_region(&mut self, base: u64, size: u64) -> Result<(), GuestMemoryError> {
        if size == 0 {
            return Err(GuestMemoryError::EmptyMapping);
        }
        let index = self
            .map
            .regions
            .iter()
            .position(|region| region.base == base && region.size == size)
            .ok_or(GuestMemoryError::Unmapped {
                addr: base,
                size: usize::try_from(size).unwrap_or(usize::MAX),
            })?;
        self.map.regions.remove(index);
        Ok(())
    }

    pub fn permissions_at(&self, addr: u64) -> Option<MemoryPermission> {
        self.map
            .regions
            .iter()
            .find(|region| region.contains_range(addr, 1))
            .map(MemoryRegion::permissions)
    }

    pub fn load_bytes(&mut self, addr: u64, bytes: &[u8]) -> Result<(), GuestMemoryError> {
        let region = self.region_mut(addr, bytes.len())?;
        let offset = region.offset(addr);
        region.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn read_bytes(&self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
        self.check_permission(addr, size, MemoryPermission::READ)?;
        let region = self.region(addr, size)?;
        let offset = region.offset(addr);
        Ok(region.data[offset..offset + size].to_vec())
    }

    pub fn fetch_bytes(&self, addr: u64, size: usize) -> Result<Vec<u8>, GuestMemoryError> {
        self.check_permission(addr, 1, MemoryPermission::EXECUTE)?;
        let region = self.region(addr, size)?;
        let offset = region.offset(addr);
        Ok(region.data[offset..offset + size].to_vec())
    }

    pub fn write_bytes(&mut self, addr: u64, bytes: &[u8]) -> Result<(), GuestMemoryError> {
        self.check_permission(addr, bytes.len(), MemoryPermission::WRITE)?;
        self.load_bytes(addr, bytes)
    }

    pub fn read_u8(&self, addr: u64) -> Result<u8, GuestMemoryError> {
        Ok(self.read_bytes(addr, 1)?[0])
    }

    pub fn read_u16(&self, addr: u64) -> Result<u16, GuestMemoryError> {
        let bytes = self.read_bytes(addr, 2)?;
        Ok(u16::from_le_bytes(bytes.try_into().expect("u16 length")))
    }

    pub fn read_u32(&self, addr: u64) -> Result<u32, GuestMemoryError> {
        let bytes = self.read_bytes(addr, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("u32 length")))
    }

    pub fn read_u64(&self, addr: u64) -> Result<u64, GuestMemoryError> {
        let bytes = self.read_bytes(addr, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("u64 length")))
    }

    pub fn write_u8(&mut self, addr: u64, value: u8) -> Result<(), GuestMemoryError> {
        self.write_bytes(addr, &[value])
    }

    pub fn write_u16(&mut self, addr: u64, value: u16) -> Result<(), GuestMemoryError> {
        self.write_bytes(addr, &value.to_le_bytes())
    }

    pub fn write_u32(&mut self, addr: u64, value: u32) -> Result<(), GuestMemoryError> {
        self.write_bytes(addr, &value.to_le_bytes())
    }

    pub fn write_u64(&mut self, addr: u64, value: u64) -> Result<(), GuestMemoryError> {
        self.write_bytes(addr, &value.to_le_bytes())
    }

    fn check_permission(
        &self,
        addr: u64,
        size: usize,
        required: MemoryPermission,
    ) -> Result<(), GuestMemoryError> {
        let region = self.region(addr, size)?;
        if !region.permissions.contains(required) {
            return Err(GuestMemoryError::Permission {
                addr,
                size,
                required,
            });
        }
        Ok(())
    }

    fn region(&self, addr: u64, size: usize) -> Result<&MemoryRegion, GuestMemoryError> {
        let index = self
            .map
            .find_index(addr, size)
            .ok_or(GuestMemoryError::Unmapped { addr, size })?;
        Ok(&self.map.regions[index])
    }

    fn region_mut(
        &mut self,
        addr: u64,
        size: usize,
    ) -> Result<&mut MemoryRegion, GuestMemoryError> {
        let index = self
            .map
            .find_index(addr, size)
            .ok_or(GuestMemoryError::Unmapped { addr, size })?;
        Ok(&mut self.map.regions[index])
    }
}

fn ranges_overlap(left: Range<u64>, right: Range<u64>) -> bool {
    left.start < right.end && right.start < left.end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_reads_and_writes_memory() {
        let mut memory = GuestMemory::new();
        memory
            .map_region(
                0x1000,
                PAGE_SIZE,
                MemoryPermission::READ | MemoryPermission::WRITE,
                Some("data".to_string()),
            )
            .unwrap();

        memory.write_u64(0x1080, 0xfeed_face_cafe_beef).unwrap();

        assert_eq!(memory.read_u64(0x1080).unwrap(), 0xfeed_face_cafe_beef);
    }

    #[test]
    fn rejects_overlapping_regions() {
        let mut memory = GuestMemory::new();
        memory
            .map_region(0x1000, PAGE_SIZE, MemoryPermission::READ, None)
            .unwrap();

        let err = memory
            .map_region(0x1800, PAGE_SIZE, MemoryPermission::READ, None)
            .unwrap_err();

        assert_eq!(
            err,
            GuestMemoryError::OverlappingMapping {
                base: 0x1800,
                size: PAGE_SIZE
            }
        );
    }

    #[test]
    fn enforces_write_permissions() {
        let mut memory = GuestMemory::new();
        memory
            .map_region(0x1000, PAGE_SIZE, MemoryPermission::READ, None)
            .unwrap();

        assert!(matches!(
            memory.write_u8(0x1000, 1),
            Err(GuestMemoryError::Permission { .. })
        ));
    }

    #[test]
    fn protect_splits_region_without_overprotecting_neighbors() {
        let mut memory = GuestMemory::new();
        memory
            .map_region(
                0x1000,
                PAGE_SIZE * 3,
                MemoryPermission::READ | MemoryPermission::WRITE,
                Some("data".to_string()),
            )
            .unwrap();
        memory.write_u8(0x1000, 1).unwrap();
        memory.write_u8(0x2000, 2).unwrap();
        memory.write_u8(0x3000, 3).unwrap();

        memory
            .protect(0x2000, PAGE_SIZE as usize, MemoryPermission::READ)
            .unwrap();

        assert_eq!(memory.map().regions().len(), 3);
        memory.write_u8(0x1000, 4).unwrap();
        memory.write_u8(0x3000, 5).unwrap();
        assert!(matches!(
            memory.write_u8(0x2000, 6),
            Err(GuestMemoryError::Permission { .. })
        ));
        assert_eq!(memory.read_u8(0x2000).unwrap(), 2);
    }

    #[test]
    fn unmaps_exact_region() {
        let mut memory = GuestMemory::new();
        memory
            .map_region(0x1000, PAGE_SIZE, MemoryPermission::READ, None)
            .unwrap();

        memory.unmap_region(0x1000, PAGE_SIZE).unwrap();

        assert!(matches!(
            memory.read_u8(0x1000),
            Err(GuestMemoryError::Unmapped { .. })
        ));
    }
}
