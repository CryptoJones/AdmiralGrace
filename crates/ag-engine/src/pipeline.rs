//! Segment decode and the unfinished whole-procedure decompiler entry.
//!
//! [`Disasm::decode`] walks a byte slice with a [`CpuContext`], recording
//! one invalid byte at a time so padding does not hide the code after it.
//! [`decompile_procedure`] is still a stub: function lifting goes through
//! [`crate::lift`], not this path.

use crate::ast::AstNode;
use crate::cfg::{HighLevelProcedure, ProcedureCfg};
use crate::cpu_context::{CpuContext, DecodedInsn};
use crate::procedure::FunctionSignature;

pub struct DecompilerOptions {
    pub remove_dead_code: bool,
    pub remove_goto: bool,
    pub no_code_duplication: bool,
    pub remove_hilo_macros: bool,
    pub remove_nops: bool,
}

impl Default for DecompilerOptions {
    fn default() -> Self {
        Self {
            remove_dead_code: true,
            remove_goto: false,
            no_code_duplication: false,
            remove_hilo_macros: false,
            remove_nops: true,
        }
    }
}

pub struct Census {
    pub cancel_requested: std::sync::atomic::AtomicBool,
}

/// The decoded instructions of one segment.
///
/// `instructions` is in ascending address order. [`Disasm::decode`] pushes
/// them that way, and [`Disasm::range`] and [`Disasm::instruction_at`]
/// binary-search on it, so whatever else builds a `Disasm` must sort the
/// instructions by address first.
#[derive(Debug, Default)]
pub struct Disasm {
    pub file_offset_of_segment: u64,
    pub instructions: Vec<DecodedInsn>,
}

impl Disasm {
    /// Decode every instruction of a segment, in address order.
    ///
    /// Bytes that do not decode are recorded one at a time as
    /// [`crate::cpu_context::Flow::Invalid`] entries rather than aborting the segment, so the code
    /// after padding or a jump table is still reached. A decoder error (not an
    /// invalid encoding) still fails the decode.
    pub fn decode(
        ctx: &mut dyn CpuContext,
        segment_bytes: &[u8],
        segment_base: u64,
    ) -> anyhow::Result<Disasm> {
        let mut instructions = Vec::new();
        let mut cursor = 0usize;
        while cursor < segment_bytes.len() {
            let ins = ctx.decode(&segment_bytes[cursor..], segment_base + cursor as u64)?;
            cursor += ins.length.max(1);
            instructions.push(ins);
        }
        Ok(Disasm {
            file_offset_of_segment: 0,
            instructions,
        })
    }

    /// The instructions whose address is in `[from, to)`, in address order.
    ///
    /// Found by binary search on the order of `instructions`. Empty when no
    /// instruction starts in the range, or when `to <= from`.
    pub fn range(&self, from: u64, to: u64) -> &[DecodedInsn] {
        let start = self.instructions.partition_point(|i| i.address < from);
        let tail = &self.instructions[start..];
        &tail[..tail.partition_point(|i| i.address < to)]
    }

    /// The instruction that starts at `address`, when one does.
    ///
    /// Found by binary search on the order of `instructions`.
    pub fn instruction_at(&self, address: u64) -> Option<&DecodedInsn> {
        let at = self.instructions.partition_point(|i| i.address < address);
        self.instructions.get(at).filter(|i| i.address == address)
    }
}

pub trait InstructionLifter {
    fn decompile_instruction(
        &mut self,
        ins: &DecodedInsn,
        add_node: &mut dyn FnMut(AstNode),
    ) -> anyhow::Result<()>;
}

pub fn decompile_procedure(
    cfg: &ProcedureCfg,
    sig: &FunctionSignature,
    opts: &DecompilerOptions,
) -> anyhow::Result<(HighLevelProcedure, Vec<String>)> {
    let _ = (cfg, sig, opts);
    anyhow::bail!("not implemented: raw lifter pending")
}

/// Post-parse AST transformations (xor-to-zero, constant folding, macros).
pub fn transform_expressions(root: &mut AstNode) -> bool {
    let _ = root;
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Bitness;
    use crate::cfg::ProcedureCfg;
    use crate::cpu_context::X86IcedContext;
    use crate::procedure::FunctionSignature;

    #[test]
    fn defaults_drop_dead_code_and_nops() {
        let opts = DecompilerOptions::default();
        assert!(opts.remove_dead_code);
        assert!(opts.remove_nops);
        assert!(!opts.remove_goto);
        assert!(!opts.no_code_duplication);
        assert!(!opts.remove_hilo_macros);
    }

    #[test]
    fn decode_keeps_going_past_a_bad_byte() {
        // `90` nop, `06` (push es, not an instruction in long mode), `c3` ret.
        let mut ctx = X86IcedContext::new(Bitness::Bits64);
        let disasm = Disasm::decode(&mut ctx, &[0x90, 0x06, 0xc3], 0x1000).unwrap();
        assert_eq!(disasm.instructions.len(), 3);
        assert_eq!(disasm.instruction_at(0x1000).map(|i| i.length), Some(1));
        assert_eq!(disasm.instruction_at(0x1002).map(|i| i.address), Some(0x1002));
        assert!(disasm.instruction_at(0x1003).is_none());
    }

    #[test]
    fn instruction_at_and_range_match_a_linear_scan() {
        // Two blocks: `nop; xor eax, eax; jmp +0` at 0x1000..0x1005, then
        // `mov rbx, rax; nop; ret` at 0x1005..0x100a.
        let bytes = [0x90, 0x31, 0xc0, 0xeb, 0x00, 0x48, 0x89, 0xc3, 0x90, 0xc3];
        let mut ctx = X86IcedContext::new(Bitness::Bits64);
        let disasm = Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();
        let addresses = |instructions: &[DecodedInsn]| -> Vec<u64> {
            instructions.iter().map(|i| i.address).collect()
        };
        assert_eq!(
            addresses(&disasm.instructions),
            [0x1000, 0x1001, 0x1003, 0x1005, 0x1008, 0x1009]
        );

        // Each block is exactly its own instructions.
        assert_eq!(
            addresses(disasm.range(0x1000, 0x1005)),
            [0x1000, 0x1001, 0x1003]
        );
        assert_eq!(
            addresses(disasm.range(0x1005, 0x100a)),
            [0x1005, 0x1008, 0x1009]
        );

        // Every range over and around the segment equals a filter of the
        // whole vector: bounds inside an instruction, empty and inverted
        // ranges, and ranges outside the segment included.
        for from in 0x0ffe_u64..=0x100c {
            for to in 0x0ffe_u64..=0x100c {
                let scanned: Vec<u64> = disasm
                    .instructions
                    .iter()
                    .filter(|i| from <= i.address && i.address < to)
                    .map(|i| i.address)
                    .collect();
                assert_eq!(
                    addresses(disasm.range(from, to)),
                    scanned,
                    "range({from:#x}, {to:#x})"
                );
            }
        }

        // The binary search finds the very instruction a linear find does,
        // and misses where it misses.
        for address in 0x0ffe_u64..=0x100c {
            let scanned = disasm.instructions.iter().find(|i| i.address == address);
            assert_eq!(
                disasm
                    .instruction_at(address)
                    .map(|i| i as *const DecodedInsn),
                scanned.map(|i| i as *const DecodedInsn),
                "instruction_at({address:#x})"
            );
        }
        assert!(disasm.instruction_at(0x0fff).is_none());
        assert!(disasm.instruction_at(0x1002).is_none());
        assert!(disasm.instruction_at(0x100a).is_none());
    }

    #[test]
    fn expression_rewrite_is_still_a_no_op() {
        let mut node = AstNode::Constant {
            value: 1,
            width_bytes: 4,
        };
        assert!(!transform_expressions(&mut node));
    }

    #[test]
    fn procedure_decompile_is_not_implemented() {
        let err = decompile_procedure(
            &ProcedureCfg::default(),
            &FunctionSignature {
                name: None,
                return_type: None,
                calling_convention: None,
                args: Vec::new(),
                variadic: false,
            },
            &DecompilerOptions::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not implemented"));
    }
}
