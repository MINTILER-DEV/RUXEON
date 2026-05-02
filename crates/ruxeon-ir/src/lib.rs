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

    pub fn clear(&mut self) {
        if !self.blocks.is_empty() {
            self.invalidations += 1;
        }
        self.blocks.clear();
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
}
