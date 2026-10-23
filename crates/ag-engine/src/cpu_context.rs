use crate::register::RegisterId;

pub const RC_NONE: u32 = 0;
pub const RC_GPR: u32 = 1;
/// The vector register file: `xmm`, `ymm` and `zmm` are three widths of the same
/// 32 registers, told apart by the id's `bit_size`.
pub const RC_VEC: u32 = 2;
pub const RC_FLAGS: u32 = 5;
pub const RC_SEG: u32 = 6;
pub const RC_IP: u32 = 7;
pub const RC_FPU: u32 = 8;
pub const RC_MM: u32 = 9;
pub const RC_KMASK: u32 = 10;
pub const RC_CR: u32 = 11;
pub const RC_DR: u32 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Register(RegisterId),
    Imm(i128),
    Mem {
        base: RegisterId,
        index: RegisterId,
        scale: u32,
        disp: i64,
        size: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Next,
    UnconditionalBranch(u64),
    ConditionalBranch(u64),
    IndirectBranch,
    Call(u64),
    IndirectCall,
    Return,
    /// A software interrupt (`int n`, `int3`, `into`); control normally returns to the next instruction.
    Interrupt,
    /// A system call (`syscall`, `sysenter`); control normally returns to the next instruction.
    Syscall,
    /// An instruction that always faults (`ud2`, `ud0`, `ud1`); nothing follows it in the fall-through sense.
    Trap,
    /// `xbegin`: starts a transaction whose abort handler is at the given address, otherwise falls through.
    Xbegin(u64),
    /// Bytes that do not decode as an instruction. The decoder records one
    /// byte and moves on; the CFG walk treats it as the end of a block.
    Invalid,
}

#[derive(Debug, Clone)]
pub struct DecodedInsn {
    pub address: u64,
    pub length: usize,
    pub mnemonic: u32,
    pub flow: Flow,
    pub operands: Vec<Operand>,
    pub rip_relative_address: Option<u64>,
    pub switch_indices: bool,
}

pub trait CpuContext {
    fn decode(&mut self, bytes: &[u8], address: u64) -> anyhow::Result<DecodedInsn>;
    fn byte_size(&self) -> u64 {
        8
    }
    fn search_for_switch_case(
        &mut self,
        _ins: &DecodedInsn,
        _for_procedure: u64,
        _bb: u64,
    ) -> anyhow::Result<bool> {
        Ok(false)
    }
}

pub struct X86IcedContext {
    options: u32,
}

impl Default for X86IcedContext {
    fn default() -> Self {
        Self {
            options: iced_x86::DecoderOptions::NONE,
        }
    }
}

/// The engine's id for an iced register.
///
/// The id names the full register (`AH`, `AX`, `EAX` and `RAX` all share GPR
/// 0) and records the slice the operand covers, so `AH` is 8 bits at offset 8
/// and `RSP` is GPR 4 — they never collide. Vector registers of every width
/// share one class, numbered 0..32; segment, mask, control, debug, MMX and x87
/// registers keep their own numbering.
fn reg_id(r: iced_x86::Register) -> RegisterId {
    use iced_x86::Register as R;
    if r == R::None {
        return RegisterId::new(RC_NONE, 0, 0);
    }
    let bits = r.size() as u32 * 8;
    if r.is_gpr() {
        let full = r.full_register();
        let offset = if r >= R::AH && r <= R::BH { 8 } else { 0 };
        return RegisterId::slice(RC_GPR, full.number() as u32, bits, offset);
    }
    if r.is_vector_register() {
        return RegisterId::new(RC_VEC, r.number() as u32, bits);
    }
    if r == R::RIP || r == R::EIP {
        return RegisterId::new(RC_IP, 0, bits);
    }
    let class = if r.is_segment_register() {
        RC_SEG
    } else if r.is_k() {
        RC_KMASK
    } else if r.is_cr() {
        RC_CR
    } else if r.is_dr() {
        RC_DR
    } else if r.is_mm() {
        RC_MM
    } else if r.is_st() {
        RC_FPU
    } else {
        RC_NONE
    };
    RegisterId::new(class, r.number() as u32, bits)
}

impl CpuContext for X86IcedContext {
    fn decode(&mut self, bytes: &[u8], address: u64) -> anyhow::Result<DecodedInsn> {
        let mut dec = iced_x86::Decoder::with_ip(64, bytes, address, self.options);
        let ins = dec.decode();
        if ins.is_invalid() {
            // One byte of data in a code section, not an instruction. It is
            // recorded, not fatal: a segment decode must get past padding and
            // tables to the code after them.
            return Ok(DecodedInsn {
                address,
                length: 1,
                mnemonic: iced_x86::Mnemonic::INVALID as u32,
                flow: Flow::Invalid,
                operands: Vec::new(),
                rip_relative_address: None,
                switch_indices: false,
            });
        }
        let mnemonic = ins.mnemonic() as u32;
        let flow = match ins.flow_control() {
            _ if matches!(
                ins.mnemonic(),
                iced_x86::Mnemonic::Syscall | iced_x86::Mnemonic::Sysenter
            ) =>
            {
                Flow::Syscall
            }
            iced_x86::FlowControl::Next => Flow::Next,
            iced_x86::FlowControl::UnconditionalBranch => {
                Flow::UnconditionalBranch(ins.near_branch_target())
            }
            iced_x86::FlowControl::ConditionalBranch => {
                Flow::ConditionalBranch(ins.near_branch_target())
            }
            iced_x86::FlowControl::IndirectBranch => Flow::IndirectBranch,
            iced_x86::FlowControl::Call => Flow::Call(ins.near_branch_target()),
            iced_x86::FlowControl::IndirectCall => Flow::IndirectCall,
            iced_x86::FlowControl::Return => Flow::Return,
            iced_x86::FlowControl::Interrupt => Flow::Interrupt,
            iced_x86::FlowControl::Exception => Flow::Trap,
            iced_x86::FlowControl::XbeginXabortXend => match ins.mnemonic() {
                iced_x86::Mnemonic::Xbegin => Flow::Xbegin(ins.near_branch_target()),
                _ => Flow::Next,
            },
        };
        let mut operands = Vec::with_capacity(4);
        for i in 0..ins.op_count() {
            let op = ins.op_kind(i);
            let o = match op {
                iced_x86::OpKind::Register => Operand::Register(reg_id(ins.op_register(i))),
                iced_x86::OpKind::Immediate8
                | iced_x86::OpKind::Immediate8_2nd
                | iced_x86::OpKind::Immediate16
                | iced_x86::OpKind::Immediate32
                | iced_x86::OpKind::Immediate64 => Operand::Imm(ins.immediate(i) as i128),
                iced_x86::OpKind::Immediate8to16
                | iced_x86::OpKind::Immediate8to32
                | iced_x86::OpKind::Immediate8to64
                | iced_x86::OpKind::Immediate32to64 => match op {
                    iced_x86::OpKind::Immediate8to16 => Operand::Imm(ins.immediate8to16() as i128),
                    iced_x86::OpKind::Immediate8to32 => Operand::Imm(ins.immediate8to32() as i128),
                    iced_x86::OpKind::Immediate8to64 => Operand::Imm(ins.immediate8to64() as i128),
                    _ => Operand::Imm(ins.immediate32to64() as i128),
                },
                iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64 => Operand::Imm(ins.near_branch_target() as i128),
                iced_x86::OpKind::FarBranch16 | iced_x86::OpKind::FarBranch32 => Operand::Imm(
                    ((ins.far_branch_selector() as i128) << 32) | ins.far_branch32() as i128,
                ),
                _ => Operand::Mem {
                    base: reg_id(ins.memory_base()),
                    index: reg_id(ins.memory_index()),
                    scale: ins.memory_index_scale(),
                    disp: ins.memory_displacement64() as i64,
                    size: ins.memory_size().size() as u32,
                },
            };
            operands.push(o);
        }
        let rip_relative_address = if ins.is_ip_rel_memory_operand() {
            Some(ins.ip_rel_memory_address())
        } else {
            None
        };
        Ok(DecodedInsn {
            address,
            length: ins.len(),
            mnemonic,
            flow,
            operands,
            rip_relative_address,
            switch_indices: false,
        })
    }

    fn byte_size(&self) -> u64 {
        8
    }
}
