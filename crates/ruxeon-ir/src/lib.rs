//! Ruxeon IR block metadata and cache.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BasicBlockId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrInstructionKind {
    Compute,
    Branch,
    Call,
    Return,
    Syscall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrInstruction {
    pub ip: u64,
    pub len: u8,
    pub text: String,
    pub kind: IrInstructionKind,
}

impl IrInstruction {
    pub fn end_ip(&self) -> u64 {
        self.ip + u64::from(self.len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockTerminator {
    FallThrough,
    Branch,
    Call,
    Return,
    Syscall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    pub id: BasicBlockId,
    pub start_ip: u64,
    pub end_ip: u64,
    pub instructions: Vec<IrInstruction>,
    pub terminator: BlockTerminator,
}

impl BasicBlock {
    pub fn new(
        start_ip: u64,
        instructions: Vec<IrInstruction>,
        terminator: BlockTerminator,
    ) -> Self {
        let end_ip = instructions
            .last()
            .map(IrInstruction::end_ip)
            .unwrap_or(start_ip);
        Self {
            id: BasicBlockId(start_ip),
            start_ip,
            end_ip,
            instructions,
            terminator,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockCacheStats {
    pub blocks: usize,
    pub hits: u64,
    pub misses: u64,
    pub invalidations: u64,
}

#[derive(Debug, Clone, Default)]
pub struct BlockCache {
    blocks: HashMap<BasicBlockId, BasicBlock>,
    hits: u64,
    misses: u64,
    invalidations: u64,
}

impl BlockCache {
    pub fn get(&mut self, id: BasicBlockId) -> Option<BasicBlock> {
        match self.blocks.get(&id) {
            Some(block) => {
                self.hits += 1;
                Some(block.clone())
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    pub fn insert(&mut self, block: BasicBlock) {
        self.blocks.insert(block.id, block);
    }

    /// Look up a block without updating hit/miss counters.
    pub fn get_without_stats(&self, id: BasicBlockId) -> Option<&BasicBlock> {
        self.blocks.get(&id)
    }

    /// Remove all cached blocks whose instruction range overlaps
    /// `[addr, addr+size)`.  Returns the number of blocks removed.
    pub fn invalidate_range(&mut self, addr: u64, size: u64) -> usize {
        let end = addr.saturating_add(size);
        let before = self.blocks.len();
        self.blocks
            .retain(|_, block| block.end_ip <= addr || block.start_ip >= end);
        let removed = before - self.blocks.len();
        if removed > 0 {
            self.invalidations += removed as u64;
        }
        removed
    }

    pub fn clear(&mut self) {
        let count = self.blocks.len();
        if count > 0 {
            self.invalidations += count as u64;
        }
        self.blocks.clear();
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn stats(&self) -> BlockCacheStats {
        BlockCacheStats {
            blocks: self.blocks.len(),
            hits: self.hits,
            misses: self.misses,
            invalidations: self.invalidations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_blocks_and_tracks_stats() {
        let mut cache = BlockCache::default();
        let id = BasicBlockId(0x1000);

        assert!(cache.get(id).is_none());
        cache.insert(BasicBlock::new(
            id.0,
            vec![IrInstruction {
                ip: id.0,
                len: 1,
                text: "nop".to_string(),
                kind: IrInstructionKind::Compute,
            }],
            BlockTerminator::FallThrough,
        ));
        assert!(cache.get(id).is_some());

        let stats = cache.stats();
        assert_eq!(stats.blocks, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);

        cache.clear();
        assert_eq!(cache.stats().blocks, 0);
        assert_eq!(cache.stats().invalidations, 1);
    }

    #[test]
    fn invalidate_range_removes_only_overlapping_blocks() {
        let mut cache = BlockCache::default();

        // Block A: covers [0x1000..0x1005)
        cache.insert(BasicBlock::new(
            0x1000,
            vec![IrInstruction {
                ip: 0x1000,
                len: 5,
                text: "call foo".to_string(),
                kind: IrInstructionKind::Call,
            }],
            BlockTerminator::Call,
        ));

        // Block B: covers [0x2000..0x2003)
        cache.insert(BasicBlock::new(
            0x2000,
            vec![
                IrInstruction {
                    ip: 0x2000,
                    len: 1,
                    text: "nop".to_string(),
                    kind: IrInstructionKind::Compute,
                },
                IrInstruction {
                    ip: 0x2001,
                    len: 2,
                    text: "ret".to_string(),
                    kind: IrInstructionKind::Return,
                },
            ],
            BlockTerminator::Return,
        ));

        // Block C: covers [0x3000..0x3002)
        cache.insert(BasicBlock::new(
            0x3000,
            vec![IrInstruction {
                ip: 0x3000,
                len: 2,
                text: "jmp short +0".to_string(),
                kind: IrInstructionKind::Branch,
            }],
            BlockTerminator::Branch,
        ));

        assert_eq!(cache.len(), 3);

        // Invalidate range [0x2001..0x2003) — only overlaps block B.
        let removed = cache.invalidate_range(0x2001, 2);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 2);
        assert!(cache.get_without_stats(BasicBlockId(0x1000)).is_some());
        assert!(cache.get_without_stats(BasicBlockId(0x2000)).is_none());
        assert!(cache.get_without_stats(BasicBlockId(0x3000)).is_some());

        // Invalidate a range that doesn't overlap anything.
        let removed = cache.invalidate_range(0x4000, 0x1000);
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 2);

        // Invalidate a wide range covering both remaining blocks.
        let removed = cache.invalidate_range(0x0000, 0x4000);
        assert_eq!(removed, 2);
        assert!(cache.is_empty());
    }
}
