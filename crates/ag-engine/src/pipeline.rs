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
