//! Ruxeon IR block metadata and cache.

use iced_x86::Register;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrOperand {
    Reg(Register),
    Imm(u64),
    Mem {
        base: Register,
        index: Register,
        scale: u8,
        disp: i64,
        size: u32,
    },
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrOpcode {
    Nop,
    Mov,
    Add,
    Sub,
    Xor,
    And,
    Or,
    Cmp,
    Test,
    Push,
    Pop,
    Load,
    Store,
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrInstruction {
    pub ip: u64,
    pub len: u8,
    pub text: String,
    pub kind: IrInstructionKind,
    pub opcode: IrOpcode,
    pub op0: IrOperand,
    pub op1: IrOperand,
    pub op2: IrOperand,
    pub width: u32,
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
                opcode: IrOpcode::Nop,
                op0: IrOperand::None,
                op1: IrOperand::None,
                op2: IrOperand::None,
                width: 0,
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
