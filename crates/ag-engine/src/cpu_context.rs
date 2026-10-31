use crate::arch::Bitness;
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
    /// `hlt`: stops the processor; nothing follows it in the fall-through sense.
    Halt,
    /// `xbegin`: starts a transaction whose abort handler is at the given address, otherwise falls through.
    Xbegin(u64),
    /// Bytes that do not decode as an instruction. The decoder records one
    /// byte and moves on; the CFG walk treats it as the end of a block.
    Invalid,
}

/// How an instruction touches a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read, and not written.
    Read,
    /// Written, and not read: the old value is gone.
    Write,
    /// Read and then written.
    ReadWrite,
    /// Written only under a condition (`cmovcc`, `cmpxchg`): the old value
    /// may survive.
    CondWrite,
}

impl Access {
    /// Whether the register's old value is read.
    pub fn reads(self) -> bool {
        matches!(self, Access::Read | Access::ReadWrite)
    }

    /// Whether the register's old value is certainly gone.
    pub fn kills(self) -> bool {
        matches!(self, Access::Write | Access::ReadWrite)
    }
}

/// One register an instruction touches, with how.
///
/// The register is the slice the instruction names — `eax`, not `rax`, for
/// `mov [rbp-0xc], eax` — so the width of a read is known. The registers a
/// memory operand is addressed through are read; the ones an instruction
/// uses implicitly (`cdqe` reads `eax` and writes `rax`, `push` reads and
/// writes `rsp`) are listed too. `xor r, r` and `sub r, r` write their
/// register without reading it: they are the idiom for zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterUse {
    pub register: RegisterId,
    pub access: Access,
}

#[derive(Debug, Clone)]
pub struct DecodedInsn {
    pub address: u64,
    pub length: usize,
    pub mnemonic: u32,
    pub flow: Flow,
    pub operands: Vec<Operand>,
    /// The registers the instruction reads and writes, explicit and
    /// implicit, by the slice it names. Empty for bytes that do not decode.
    pub register_uses: Vec<RegisterUse>,
    /// The address a RIP-relative memory operand names: `[rip+disp]` resolved
    /// against the next instruction. That is how 64-bit code names its data;
    /// 32-bit code has no such operand, so this is `None` there.
    pub rip_relative_address: Option<u64>,
    /// The address an absolute memory operand names: `[disp]` with no base,
    /// no index and no segment override, so the displacement is the address.
    /// That is how 32-bit code names its data; 64-bit code does it too when
    /// it is not position-independent.
    pub absolute_address: Option<u64>,
    pub switch_indices: bool,
    /// The instruction's form, as the decoder numbers it: iced-x86's `Code`
    /// for x86, so `mov eax, [rbp-0xc]` and `mov [rbp-0xc], eax` are two
    /// forms of one mnemonic. 0 where the decoder has no such number.
    pub opcode: u32,
    /// The flags the instruction reads, as the decoder's bits (`RflagsBits`
    /// for x86); 0 where it tracks none. [`flag_names`] spells them.
    pub flags_read: u32,
    /// The flags the instruction writes — set, cleared, computed or left
    /// undefined.
    pub flags_written: u32,
}

/// The name of an instruction's form, as the x86 decoder numbers it: `None`
/// for a form it does not know, an invalid instruction among them. The
/// other decoders number nothing (0), so every form of theirs is `None`.
pub fn opcode_name(opcode: u32) -> Option<String> {
    iced_x86::Code::try_from(opcode as usize)
        .ok()
        .filter(|code| *code != iced_x86::Code::INVALID)
        .map(|code| format!("{code:?}"))
}

/// The names of the flags in a set of the x86 decoder's bits, in the order
/// the register lays them out; the other decoders report no flags.
pub fn flag_names(bits: u32) -> Vec<&'static str> {
    use iced_x86::RflagsBits;
    [
        (RflagsBits::CF, "CF"),
        (RflagsBits::PF, "PF"),
        (RflagsBits::AF, "AF"),
        (RflagsBits::ZF, "ZF"),
        (RflagsBits::SF, "SF"),
        (RflagsBits::DF, "DF"),
        (RflagsBits::OF, "OF"),
        (RflagsBits::IF, "IF"),
        (RflagsBits::AC, "AC"),
        (RflagsBits::UIF, "UIF"),
        (RflagsBits::C0, "C0"),
        (RflagsBits::C1, "C1"),
        (RflagsBits::C2, "C2"),
        (RflagsBits::C3, "C3"),
    ]
    .into_iter()
    .filter(|(bit, _)| bits & bit != 0)
    .map(|(_, name)| name)
    .collect()
}

impl DecodedInsn {
    /// The address a memory operand of the instruction names outright, when
    /// one does: the RIP-relative one in 64-bit code, the absolute one in
    /// 32-bit code. This is the pointer a reference to a string or to data
    /// is found by, in either width.
    pub fn memory_address(&self) -> Option<u64> {
        self.rip_relative_address.or(self.absolute_address)
    }
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

/// The engine's x86 decoder, over iced.
///
/// One decoder reads one width of x86: the bytes of a 32-bit program and of
/// a 64-bit program do not mean the same thing, so the width comes from the
/// image's language and is fixed when the decoder is made.
pub struct X86IcedContext {
    options: u32,
    bitness: Bitness,
}

impl Default for X86IcedContext {
    /// A 64-bit decoder.
    fn default() -> Self {
        Self::new(Bitness::Bits64)
    }
}

impl X86IcedContext {
    /// A decoder for a program of the given width.
    pub fn new(bitness: Bitness) -> Self {
        Self {
            options: iced_x86::DecoderOptions::NONE,
            bitness,
        }
    }

    /// A decoder for the program a language id names.
    ///
    /// `None` when the id names an architecture other than x86, or names no
    /// width the decoder reads: the decoder reads x86 and nothing else.
    pub fn of_language(language: &str) -> Option<Self> {
        if !Bitness::is_x86(language) {
            return None;
        }
        Some(Self::new(Bitness::of_language(language)?))
    }

    /// The width of the program this decoder reads.
    pub fn bitness(&self) -> Bitness {
        self.bitness
    }
}

/// The engine's id for an iced register.
///
/// The id names the full register (`AH`, `AX`, `EAX` and `RAX` all share GPR
/// 0) and records the slice the operand covers, so `AH` is 8 bits at offset 8
/// and `RSP` is GPR 4 — they never collide. Vector registers of every width
/// share one class, numbered 0..32; segment, mask, control, debug, MMX and x87
/// registers keep their own numbering.
///
/// The id is the same whatever the width of the program: a general register
/// is numbered by its place in the file, which `EAX` and `RAX` share, and the
/// slice is the width of the operand. In a 32-bit program `EAX` is the whole
/// of GPR 0, and its id — 32 bits at offset 0 — is the id of a whole register
/// of 32 bits; `ESP` is GPR 4 and `EIP` is the instruction pointer at 32 bits.
/// A 32-bit listing and a 64-bit one therefore name a register the same way,
/// and nothing has to be told which it is reading.
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
        let mut dec = iced_x86::Decoder::with_ip(self.bitness.bits(), bytes, address, self.options);
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
                register_uses: Vec::new(),
                rip_relative_address: None,
                absolute_address: None,
                switch_indices: false,
                opcode: 0,
                flags_read: 0,
                flags_written: 0,
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
            // iced files `hlt` under `Next`; control does not reach the
            // instruction after it.
            _ if ins.mnemonic() == iced_x86::Mnemonic::Hlt => Flow::Halt,
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
        let absolute_address = absolute_address(&ins);
        Ok(DecodedInsn {
            address,
            length: ins.len(),
            mnemonic,
            flow,
            operands,
            register_uses: register_uses(&ins),
            rip_relative_address,
            absolute_address,
            switch_indices: false,
            opcode: ins.code() as u32,
            flags_read: ins.rflags_read(),
            flags_written: ins.rflags_modified(),
        })
    }

    fn byte_size(&self) -> u64 {
        self.bitness.byte_size()
    }
}

/// The registers `ins` reads and writes, as iced's instruction information
/// reports them: one entry per register and role, by the slice the
/// instruction touches. A 32-bit write zero-extends, so iced reports
/// `add eax, 1` as a read of `eax` and a write of `rax`, and the zeroing
/// idioms `xor r, r` and `sub r, r` as a write alone.
fn register_uses(ins: &iced_x86::Instruction) -> Vec<RegisterUse> {
    use iced_x86::OpAccess;
    let mut factory = iced_x86::InstructionInfoFactory::new();
    let mut uses: Vec<RegisterUse> = Vec::new();
    for used in factory.info(ins).used_registers() {
        let access = match used.access() {
            OpAccess::Read | OpAccess::CondRead | OpAccess::ReadCondWrite => Access::Read,
            OpAccess::Write => Access::Write,
            OpAccess::CondWrite => Access::CondWrite,
            OpAccess::ReadWrite => Access::ReadWrite,
            OpAccess::None | OpAccess::NoMemAccess => continue,
        };
        let use_ = RegisterUse {
            register: reg_id(used.register()),
            access,
        };
        // `test eax, eax` names the register twice; one entry says it.
        if !uses.contains(&use_) {
            uses.push(use_);
        }
    }
    uses
}

/// The address an absolute memory operand of `ins` names, when it has one.
///
/// A memory operand with no base register and no index register is the
/// displacement alone, and the displacement is an address: `mov eax, [0x804b008]`
/// reads the data at that address. A segment override takes the operand out of
/// the flat address space — `fs:[0x28]` is the stack guard, not the 40th byte
/// of the program — so an operand with one names nothing. An operand that is
/// relative to the instruction pointer has a base, and is left to
/// [`DecodedInsn::rip_relative_address`].
fn absolute_address(ins: &iced_x86::Instruction) -> Option<u64> {
    use iced_x86::{OpKind, Register as R};
    let has_memory = (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory);
    if !has_memory
        || ins.memory_base() != R::None
        || ins.memory_index() != R::None
        || ins.segment_prefix() != R::None
    {
        return None;
    }
    Some(ins.memory_displacement64())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode one 64-bit instruction at 0x1000.
    fn one(bytes: &[u8]) -> DecodedInsn {
        X86IcedContext::default()
            .decode(bytes, 0x1000)
            .expect("the bytes decode")
    }

    /// How the instruction touches GPR 0 — `rax` or a slice of it — as
    /// `(bits, access)`.
    fn rax_use(bytes: &[u8]) -> Vec<(u32, Access)> {
        one(bytes)
            .register_uses
            .iter()
            .filter(|use_| use_.register.class == RC_GPR && use_.register.index == 0)
            .map(|use_| {
                (
                    use_.register.bit_size + use_.register.bit_offset,
                    use_.access,
                )
            })
            .collect()
    }

    #[test]
    fn a_store_of_eax_reads_it_and_a_load_into_eax_writes_it() {
        // mov [rbp-0xc], eax
        assert_eq!(rax_use(&[0x89, 0x45, 0xf4]), vec![(32, Access::Read)]);
        // mov rax, [rbp-8]
        assert_eq!(
            rax_use(&[0x48, 0x8b, 0x45, 0xf8]),
            vec![(64, Access::Write)]
        );
        // mov edi, eax
        assert_eq!(rax_use(&[0x89, 0xc7]), vec![(32, Access::Read)]);
    }

    #[test]
    fn compares_read_and_arithmetic_reads_and_writes() {
        // test eax, eax
        assert_eq!(rax_use(&[0x85, 0xc0]), vec![(32, Access::Read)]);
        // cmp rax, 1
        assert_eq!(rax_use(&[0x48, 0x83, 0xf8, 0x01]), vec![(64, Access::Read)]);
        // add eax, 1: a 32-bit write zero-extends into rax, so the old
        // value is read as eax and the whole register is written.
        assert_eq!(
            rax_use(&[0x83, 0xc0, 0x01]),
            vec![(32, Access::Read), (64, Access::Write)]
        );
        // mul rcx reads and writes rax whole.
        assert_eq!(rax_use(&[0x48, 0xf7, 0xe1]), vec![(64, Access::ReadWrite)]);
    }

    #[test]
    fn the_zeroing_idioms_only_write() {
        // xor eax, eax; sub rax, rax; xor eax, ecx
        assert_eq!(rax_use(&[0x31, 0xc0]), vec![(64, Access::Write)]);
        assert_eq!(rax_use(&[0x48, 0x29, 0xc0]), vec![(64, Access::Write)]);
        assert_eq!(
            rax_use(&[0x31, 0xc8]),
            vec![(32, Access::Read), (64, Access::Write)]
        );
    }

    #[test]
    fn the_implicit_registers_are_listed_by_slice() {
        // cdqe reads eax and writes rax
        let uses = rax_use(&[0x48, 0x98]);
        assert!(uses.contains(&(32, Access::Read)), "{uses:?}");
        assert!(uses.contains(&(64, Access::Write)), "{uses:?}");
        // a memory operand through rax reads it: mov [rax], 1
        assert_eq!(
            rax_use(&[0xc7, 0x00, 0x01, 0x00, 0x00, 0x00]),
            vec![(64, Access::Read)]
        );
        // cmovne rax, rcx may leave rax as it was; the 32-bit form always
        // zero-extends, so its old eax is read and rax written.
        assert_eq!(
            rax_use(&[0x48, 0x0f, 0x45, 0xc1]),
            vec![(64, Access::CondWrite)]
        );
        assert_eq!(
            rax_use(&[0x0f, 0x45, 0xc1]),
            vec![(32, Access::Read), (64, Access::Write)]
        );
        // mov al, 1 writes only the low byte
        assert_eq!(rax_use(&[0xb0, 0x01]), vec![(8, Access::Write)]);
        // call rax and jmp rax read it
        assert_eq!(rax_use(&[0xff, 0xd0]), vec![(64, Access::Read)]);
        assert_eq!(rax_use(&[0xff, 0xe0]), vec![(64, Access::Read)]);
        // a direct call touches rsp, and says nothing of rax: the clobber
        // is the convention's, not the instruction's
        let call = one(&[0xe8, 0, 0, 0, 0]);
        assert!(call
            .register_uses
            .iter()
            .all(|use_| use_.register.index != 0 || use_.register.class != RC_GPR));
        // bytes that do not decode touch nothing
        assert!(one(&[0x06]).register_uses.is_empty());
    }
}
