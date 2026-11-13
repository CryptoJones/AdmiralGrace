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

    pub fn instruction_at(&self, address: u64) -> Option<&DecodedInsn> {
        self.instructions.iter().find(|i| i.address == address)
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
