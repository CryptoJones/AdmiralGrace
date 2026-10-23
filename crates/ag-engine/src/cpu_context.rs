use crate::register::RegisterId;

pub const RC_NONE: u32 = 0;
pub const RC_GPR: u32 = 1;
pub const RC_XMM: u32 = 2;
pub const RC_YMM: u32 = 3;
pub const RC_ZMM: u32 = 4;
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
    Interrupt,
    Xbegin(u64),
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

fn iced_index(r: iced_x86::Register) -> u32 {
    r.number() as u32
}

fn reg_id(r: iced_x86::Register) -> RegisterId {
    use iced_x86::Register as R;
    if r.is_gpr() {
        return RegisterId {
            class: RC_GPR,
            index: iced_index(r),
        };
    }
    if r.is_xmm() {
        return RegisterId {
            class: RC_XMM,
            index: iced_index(r),
        };
    }
    let rr = r as u32;
    let class = if r.is_ymm() {
        RC_YMM
    } else if r.is_zmm() {
        RC_ZMM
    } else if r == R::RIP || r == R::EIP {
        RC_IP
    } else if r.is_segment_register() {
        RC_SEG
    } else if r.is_k() {
        RC_KMASK
    } else if r.is_cr() {
        RC_CR
    } else if r.is_dr() {
        RC_DR
    } else if r.is_mm() {
        RC_MM
    } else if rr >= R::ST0 as u32 && rr <= R::ST7 as u32 {
        RC_FPU
    } else {
        RC_NONE
    };
    RegisterId { class, index: 0 }
}

impl CpuContext for X86IcedContext {
    fn decode(&mut self, bytes: &[u8], address: u64) -> anyhow::Result<DecodedInsn> {
        let mut dec =
            iced_x86::Decoder::with_ip(64, bytes, address, self.options);
        let ins = dec.decode();
        if ins.is_invalid() {
            anyhow::bail!("invalid instruction at {address:#x}");
        }
        let mnemonic = ins.mnemonic() as u32;
        let flow = match ins.flow_control() {
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
            other => {
                anyhow::bail!("unhandled flow control {other:?}");
            }
        };
        let mut operands = Vec::with_capacity(4);
        for i in 0..ins.op_count() {
            let op = ins.op_kind(i);
            let o = match op {
                iced_x86::OpKind::Register => Operand::Register(reg_id(ins.op_register(i))),
                iced_x86::OpKind::Immediate8 | iced_x86::OpKind::Immediate8_2nd
                | iced_x86::OpKind::Immediate16 | iced_x86::OpKind::Immediate32
                | iced_x86::OpKind::Immediate64 => Operand::Imm(ins.immediate(i) as i128),
                iced_x86::OpKind::Immediate8to16 | iced_x86::OpKind::Immediate8to32
                | iced_x86::OpKind::Immediate8to64 | iced_x86::OpKind::Immediate32to64 => {
                    match op {
                        iced_x86::OpKind::Immediate8to16 => {
                            Operand::Imm(ins.immediate8to16() as i128)
                        }
                        iced_x86::OpKind::Immediate8to32 => {
                            Operand::Imm(ins.immediate8to32() as i128)
                        }
                        iced_x86::OpKind::Immediate8to64 => {
                            Operand::Imm(ins.immediate8to64() as i128)
                        }
                        _ => Operand::Imm(ins.immediate32to64() as i128),
                    }
                }
                iced_x86::OpKind::NearBranch16 | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64 => {
                    Operand::Imm(ins.near_branch_target() as i128)
                }
                iced_x86::OpKind::FarBranch16 | iced_x86::OpKind::FarBranch32 => {
                    Operand::Imm(
                        ((ins.far_branch_selector() as i128) << 32)
                            | ins.far_branch32() as i128,
                    )
                }
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
