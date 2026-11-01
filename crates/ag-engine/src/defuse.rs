//! Def-use webs over a function's machine instructions.
//!
//! Selecting `rax` at an instruction asks for the value `rax` holds there:
//! the instructions that may have written it, and every instruction that
//! reads it. That is not every instruction that names `rax`: a later `mov
//! eax, 5` starts a new value, and the instructions that read that one
//! belong to it. The answer is read off the decoded instructions over the
//! control-flow graph, so a function the lifter refuses has it too.
//!
//! The walk is reaching definitions. Each instruction that writes a
//! register is a definition of it; the walk goes block by block from the
//! entry, each block starting from the definitions its predecessors leave
//! and handing on what it leaves, until nothing changes. An instruction
//! that reads a register reads every definition that reaches it. Two
//! definitions that reach one read are one value — a variable assigned on
//! both arms of an `if` — so the definitions are joined into webs: a web is
//! the definitions joined by the reads they share, and the reads of any of
//! them. Every register also has a definition at the entry, the value the
//! caller left there; a web that holds it is the entry value, a parameter
//! when the register is one.
//!
//! Registers are counted whole, by the 64-bit register in 64-bit code:
//! `eax`, `ax`, `al` and `ah` are parts of `rax`.
//!
//! - A write of 32 bits or more replaces the register's value: on x86-64 a
//!   write to `eax` zero-extends into `rax`, so `mov eax, 1` is a whole
//!   definition of `rax`. In 32-bit code a write to `eax` is the whole
//!   register.
//! - A write of 8 or 16 bits — `mov al, 1`, `mov ax, 1`, `mov ah, 1` —
//!   changes part of the register and keeps the rest: it reads the value
//!   before it, and it defines the register without ending the value
//!   before it, so the definitions that reach it reach on past it too.
//! - A conditional write, `cmovne rax, rcx`, is a partial one: the old
//!   value may survive.
//! - An instruction that reads a register and writes it whole, `add rax,
//!   1`, reads one value and starts another. The value at that instruction
//!   is the one it reads; [`DefUse::value_written`] gives the one it
//!   writes. In a loop the two can be one web, and the instruction is then
//!   both a definition and a use of it.
//!
//! The convention adds what the instructions do not say:
//!
//! - A `call` reads the argument registers — System V's `rdi, rsi, rdx,
//!   rcx, r8, r9`, Microsoft x64's `rcx, rdx, r8, r9` — and defines every
//!   register the callee need not keep: `rax`, `rcx`, `rdx`, `rsi`, `rdi`,
//!   `r8` to `r11` under System V, the same less `rsi` and `rdi` under
//!   Microsoft x64. `rax` holds its result. 32-bit code passes its
//!   arguments on the stack; a call there defines `eax`, `ecx` and `edx`.
//! - A `ret` reads `rax`, the value it returns.
//! - A `syscall` reads `rax`, the number, and `rdi, rsi, rdx, r10, r8, r9`,
//!   and defines `rax`, `rcx` and `r11`, as Linux's does.
//!
//! The flags are followed the same way, each on its own: `cmp` defines
//! `zf`, `je` reads it. A call defines them all.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use iced_x86::RflagsBits;

use crate::arch::Bitness;
use crate::cfg::ProcedureCfg;
use crate::cpu_context::{Access, DecodedInsn, Flow, RC_GPR};
use crate::lift::{gpr_name, Abi};
use crate::pipeline::Disasm;

/// The flags followed, as the decoder's bits, with their names.
const FLAGS: [(u32, &str); 7] = [
    (RflagsBits::CF, "cf"),
    (RflagsBits::PF, "pf"),
    (RflagsBits::AF, "af"),
    (RflagsBits::ZF, "zf"),
    (RflagsBits::SF, "sf"),
    (RflagsBits::DF, "df"),
    (RflagsBits::OF, "of"),
];

/// A register, or a flag, whose values are followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Location {
    /// A general register, whole, by its number: `rax` is 0, `r15` 15.
    Register(u32),
    /// A flag, by the decoder's bit for it.
    Flag(u32),
}

impl Location {
    /// The register or flag a name spells, at any width: `rax`, `eax`,
    /// `ax`, `al` and `ah` are all `rax`; `r8`, `r8d`, `r8w`, `r8b` and
    /// `r8l` are all `r8`; `zf` is the zero flag. Case does not matter.
    /// `None` for a name that is neither.
    pub fn parse(name: &str) -> Option<Location> {
        let name = name.trim().to_ascii_lowercase();
        if let Some(&(bit, _)) = FLAGS.iter().find(|(_, flag)| *flag == name) {
            return Some(Location::Flag(bit));
        }
        if let Some(index) = ["ah", "ch", "dh", "bh"]
            .iter()
            .position(|high| *high == name)
        {
            return Some(Location::Register(index as u32));
        }
        (0..16)
            .find(|&index| {
                [64, 32, 16, 8]
                    .iter()
                    .any(|&bits| gpr_name(index, bits) == name)
                    || (index >= 8 && name == format!("r{index}l"))
            })
            .map(Location::Register)
    }

    /// The name of the whole register, at the program's width — `rax` in
    /// 64-bit code, `eax` in 32-bit code — or of the flag.
    pub fn name(self, bitness: Bitness) -> String {
        match self {
            Location::Register(index) => gpr_name(index, bitness.bits()),
            Location::Flag(bit) => FLAGS
                .iter()
                .find(|(flag, _)| *flag == bit)
                .map_or_else(|| format!("flag {bit:#x}"), |(_, name)| name.to_string()),
        }
    }
}

/// How one instruction touches one register or flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Touch {
    /// The register or flag.
    pub location: Location,
    /// Whether the instruction reads the value before it: a read, a
    /// read-write, and a partial or conditional write, which keeps some
    /// of it.
    pub reads: bool,
    /// Whether the instruction defines it.
    pub writes: bool,
    /// Whether the definition replaces the whole value: false for a write
    /// of 8 or 16 bits and for a conditional write.
    pub whole: bool,
    /// The widest slice the instruction touches, in bits counted from the
    /// register's low end: 32 for `eax`, 16 for `ah`, 1 for a flag.
    pub width: u32,
    /// Whether the touch is the calling convention's rather than the
    /// instruction's own: a call's arguments and clobbers, a `ret`'s
    /// result.
    pub implicit: bool,
}

/// What an instruction is to a web.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// It writes the value.
    Definition,
    /// It reads the value.
    Use,
    /// It reads the value and writes it: a partial write, or a read-write
    /// in a loop whose write reaches back to itself.
    Both,
}

impl Role {
    /// The role as the reports spell it: `def`, `use`, `def, use`.
    pub fn text(self) -> &'static str {
        match self {
            Role::Definition => "def",
            Role::Use => "use",
            Role::Both => "def, use",
        }
    }
}

/// One value of a register: the instructions that may write it and the
/// instructions that read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueWeb {
    /// The register or flag.
    pub location: Location,
    /// The addresses of the instructions that define the value, in order.
    pub defs: Vec<u64>,
    /// The addresses of the instructions that read it, in order.
    pub uses: Vec<u64>,
    /// Whether the value is, on some path, the one the register held at
    /// the function's entry: a parameter, in `rdi`.
    pub entry: bool,
}

impl ValueWeb {
    /// What the instruction at `address` is to the value, when it is
    /// anything.
    pub fn role(&self, address: u64) -> Option<Role> {
        match (
            self.defs.binary_search(&address).is_ok(),
            self.uses.binary_search(&address).is_ok(),
        ) {
            (true, true) => Some(Role::Both),
            (true, false) => Some(Role::Definition),
            (false, true) => Some(Role::Use),
            (false, false) => None,
        }
    }

    /// Every instruction of the web, definitions and uses, in order.
    pub fn addresses(&self) -> Vec<u64> {
        let all: BTreeSet<u64> = self.defs.iter().chain(&self.uses).copied().collect();
        all.into_iter().collect()
    }

    /// The web in a line, as the status bar and the reports say it: `rax
    /// at 0x401005: 1 definition, 3 uses`; `rdi at 0x1149: the entry
    /// value, 1 use` for a parameter.
    pub fn summary(&self, at: u64, bitness: Bitness) -> String {
        format!(
            "{} at {at:#x}: {}",
            self.location.name(bitness),
            self.counts()
        )
    }

    /// How many definitions and uses the web has: `1 definition, 3 uses`,
    /// with `the entry value` among the definitions when it is one.
    pub fn counts(&self) -> String {
        let count =
            |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let mut parts = Vec::new();
        if !self.defs.is_empty() || !self.entry {
            parts.push(count(self.defs.len(), "definition", "definitions"));
        }
        if self.entry {
            parts.push("the entry value".to_string());
        }
        parts.push(count(self.uses.len(), "use", "uses"));
        parts.join(", ")
    }
}

/// The def-use webs of one function: for every instruction and every
/// register or flag it touches, the definitions that reach it and the web
/// they make.
#[derive(Debug, Clone)]
pub struct DefUse {
    bitness: Bitness,
    touches: BTreeMap<u64, Vec<Touch>>,
    /// Every definition, by its instruction's address; `None` for the
    /// value a register holds at the entry. A web holds the definitions of
    /// one register or flag alone.
    defs: Vec<Option<u64>>,
    /// The web of each definition, as the number of its first member.
    web: Vec<usize>,
    def_at: HashMap<(u64, Location), usize>,
    /// The definitions that reach each read.
    reaching: HashMap<(u64, Location), Vec<usize>>,
}

impl DefUse {
    /// The registers and flags the instruction at `address` touches, in
    /// order: general registers before flags. Empty for an address that is
    /// no instruction of the function.
    pub fn touches(&self, address: u64) -> &[Touch] {
        self.touches.get(&address).map_or(&[], Vec::as_slice)
    }

    /// The program's width, which names the registers.
    pub fn bitness(&self) -> Bitness {
        self.bitness
    }

    /// The value `location` holds at the instruction at `address`: the
    /// one it reads, when it reads the register, else the one it writes.
    /// `None` when the instruction does not touch it.
    pub fn value_at(&self, address: u64, location: Location) -> Option<ValueWeb> {
        if let Some(reaching) = self.reaching.get(&(address, location)) {
            return Some(match reaching.first() {
                Some(&def) => self.web_of(self.web[def], location),
                // A read in a block the walk from the entry never reaches:
                // nothing defines what it reads.
                None => ValueWeb {
                    location,
                    defs: Vec::new(),
                    uses: vec![address],
                    entry: false,
                },
            });
        }
        self.value_written(address, location)
    }

    /// The value the instruction at `address` writes into `location`, when
    /// it writes it: for `add rax, 1`, the sum, where [`Self::value_at`]
    /// is what it adds to.
    pub fn value_written(&self, address: u64, location: Location) -> Option<ValueWeb> {
        let &def = self.def_at.get(&(address, location))?;
        Some(self.web_of(self.web[def], location))
    }

    /// The web whose first definition is `root`.
    fn web_of(&self, root: usize, location: Location) -> ValueWeb {
        let mut defs = BTreeSet::new();
        let mut entry = false;
        for (index, def) in self.defs.iter().enumerate() {
            if self.web[index] != root {
                continue;
            }
            match def {
                Some(address) => {
                    defs.insert(*address);
                }
                None => entry = true,
            }
        }
        let uses: BTreeSet<u64> = self
            .reaching
            .iter()
            .filter(|((_, at), reaching)| {
                *at == location && reaching.first().is_some_and(|&def| self.web[def] == root)
            })
            .map(|((address, _), _)| *address)
            .collect();
        ValueWeb {
            location,
            defs: defs.into_iter().collect(),
            uses: uses.into_iter().collect(),
            entry,
        }
    }
}

/// The definitions reaching a point, by register or flag.
type State = BTreeMap<Location, BTreeSet<usize>>;

/// The def-use webs of the function entered at `entry` that `cfg` is the
/// graph of.
///
/// `bitness` is the program's width, which says what a whole register is;
/// `abi` the convention whose calls read the argument registers and
/// clobber the ones the callee need not keep.
pub fn register_def_use(
    disasm: &Disasm,
    cfg: &ProcedureCfg,
    entry: u64,
    bitness: Bitness,
    abi: Abi,
) -> DefUse {
    let block_of: BTreeMap<u64, usize> = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.from, index))
        .collect();
    let instructions_of = |index: usize| {
        let block = &cfg.blocks[index];
        let start = disasm
            .instructions
            .partition_point(|instruction| instruction.address < block.from);
        disasm.instructions[start..]
            .iter()
            .take_while(move |instruction| instruction.address < block.to)
    };

    // What each instruction touches, and a definition for each write.
    let mut touches: BTreeMap<u64, Vec<Touch>> = BTreeMap::new();
    let mut defs: Vec<Option<u64>> = Vec::new();
    let mut def_at: HashMap<(u64, Location), usize> = HashMap::new();
    let mut locations: BTreeSet<Location> = BTreeSet::new();
    for index in 0..cfg.blocks.len() {
        for instruction in instructions_of(index) {
            let touched = touches_of(instruction, bitness, abi);
            for touch in &touched {
                locations.insert(touch.location);
                if touch.writes {
                    def_at.insert((instruction.address, touch.location), defs.len());
                    defs.push(Some(instruction.address));
                }
            }
            touches.insert(instruction.address, touched);
        }
    }
    // The value each register holds at the entry is a definition too.
    let mut at_entry = State::new();
    for &location in &locations {
        at_entry.insert(location, BTreeSet::from([defs.len()]));
        defs.push(None);
    }

    let step = |state: &mut State,
                address: u64,
                reaching: Option<&mut HashMap<(u64, Location), Vec<usize>>>| {
        let touched = touches.get(&address).map_or(&[][..], Vec::as_slice);
        if let Some(reaching) = reaching {
            for touch in touched.iter().filter(|touch| touch.reads) {
                let reached = state
                    .get(&touch.location)
                    .map(|defs| defs.iter().copied().collect())
                    .unwrap_or_default();
                reaching.insert((address, touch.location), reached);
            }
        }
        for touch in touched.iter().filter(|touch| touch.writes) {
            let def = def_at[&(address, touch.location)];
            if touch.whole {
                state.insert(touch.location, BTreeSet::from([def]));
            } else {
                state.entry(touch.location).or_default().insert(def);
            }
        }
    };

    let mut entering: Vec<Option<State>> = vec![None; cfg.blocks.len()];
    let mut queue = VecDeque::new();
    if let Some(&first) = block_of.get(&entry) {
        entering[first] = Some(at_entry);
        queue.push_back(first);
    }
    while let Some(index) = queue.pop_front() {
        let Some(mut state) = entering[index].clone() else {
            continue;
        };
        for instruction in instructions_of(index) {
            step(&mut state, instruction.address, None);
        }
        for successor in &cfg.blocks[index].successor_addresses {
            let Some(&next) = block_of.get(successor) else {
                continue;
            };
            let joined = match &entering[next] {
                Some(held) => {
                    let mut joined = held.clone();
                    for (location, defs) in &state {
                        joined.entry(*location).or_default().extend(defs);
                    }
                    joined
                }
                None => state.clone(),
            };
            if entering[next].as_ref() != Some(&joined) {
                entering[next] = Some(joined);
                queue.push_back(next);
            }
        }
    }

    let mut reaching: HashMap<(u64, Location), Vec<usize>> = HashMap::new();
    for (index, held) in entering.iter().enumerate() {
        let mut state = held.clone().unwrap_or_default();
        for instruction in instructions_of(index) {
            step(&mut state, instruction.address, Some(&mut reaching));
        }
    }

    // The definitions that reach one read are one value.
    let mut parent: Vec<usize> = (0..defs.len()).collect();
    fn find(parent: &mut [usize], mut at: usize) -> usize {
        while parent[at] != at {
            parent[at] = parent[parent[at]];
            at = parent[at];
        }
        at
    }
    for reached in reaching.values() {
        let Some((&first, rest)) = reached.split_first() else {
            continue;
        };
        for &other in rest {
            let (a, b) = (find(&mut parent, first), find(&mut parent, other));
            if a != b {
                parent[a.max(b)] = a.min(b);
            }
        }
    }
    let web = (0..defs.len()).map(|def| find(&mut parent, def)).collect();

    DefUse {
        bitness,
        touches,
        defs,
        web,
        def_at,
        reaching,
    }
}

/// The registers and flags `ins` touches, its own and the convention's.
fn touches_of(ins: &DecodedInsn, bitness: Bitness, abi: Abi) -> Vec<Touch> {
    let mut touched: BTreeMap<Location, Touch> = BTreeMap::new();
    let mut add = |location: Location, reads: bool, write: Option<bool>, width: u32, implicit| {
        let touch = touched.entry(location).or_insert(Touch {
            location,
            reads: false,
            writes: false,
            whole: false,
            width: 0,
            implicit,
        });
        touch.reads |= reads;
        if let Some(whole) = write {
            touch.writes = true;
            touch.whole |= whole;
        }
        touch.width = touch.width.max(width);
        touch.implicit &= implicit;
    };

    // In 64-bit code a 32-bit write zero-extends: it replaces the register.
    let whole_bits = bitness.bits().min(32);
    let full = bitness.bits();
    for use_ in &ins.register_uses {
        let register = use_.register;
        if register.class != RC_GPR || register.index >= 16 {
            continue;
        }
        let location = Location::Register(register.index);
        let width = register.bit_size + register.bit_offset;
        match use_.access {
            Access::Read => add(location, true, None, width, false),
            Access::Write | Access::ReadWrite => {
                let whole = register.bit_size >= whole_bits;
                let reads = use_.access == Access::ReadWrite || !whole;
                add(location, reads, Some(whole), width, false);
            }
            Access::CondWrite => add(location, true, Some(false), width, false),
        }
    }
    for (bit, _) in FLAGS {
        if ins.flags_read & bit != 0 {
            add(Location::Flag(bit), true, None, 1, false);
        }
        if ins.flags_written & bit != 0 {
            add(Location::Flag(bit), false, Some(true), 1, false);
        }
    }

    let sixty_four = bitness == Bitness::Bits64;
    match ins.flow {
        Flow::Call(_) | Flow::IndirectCall => {
            if sixty_four {
                for &argument in abi.argument_registers() {
                    add(Location::Register(argument), true, None, full, true);
                }
                for index in (0..16).filter(|&index| !abi.is_callee_saved(index)) {
                    add(Location::Register(index), false, Some(true), full, true);
                }
            } else {
                for index in [0, 1, 2] {
                    add(Location::Register(index), false, Some(true), full, true);
                }
            }
            for (bit, _) in FLAGS {
                add(Location::Flag(bit), false, Some(true), 1, true);
            }
        }
        Flow::Return => add(Location::Register(0), true, None, full, true),
        Flow::Syscall if sixty_four => {
            for index in [0, 7, 6, 2, 10, 8, 9] {
                add(Location::Register(index), true, None, full, true);
            }
            for index in [0, 1, 11] {
                add(Location::Register(index), false, Some(true), full, true);
            }
        }
        _ => {}
    }
    touched.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfgwalk::resolve_branches;
    use crate::cpu_context::X86IcedContext;

    const RAX: Location = Location::Register(0);
    const RCX: Location = Location::Register(1);
    const RDI: Location = Location::Register(7);

    /// The webs of the 64-bit code in `bytes`, as it sits at 0x1000.
    fn webs_with(bytes: &[u8], abi: Abi) -> DefUse {
        let mut ctx = X86IcedContext::new(Bitness::Bits64);
        let disasm = Disasm::decode(&mut ctx, bytes, 0x1000).unwrap();
        let cfg = resolve_branches(&disasm, 0x1000);
        register_def_use(&disasm, &cfg, 0x1000, Bitness::Bits64, abi)
    }

    fn webs(bytes: &[u8]) -> DefUse {
        webs_with(bytes, Abi::SystemV)
    }

    fn web(defs: &[u64], uses: &[u64], location: Location, entry: bool) -> ValueWeb {
        ValueWeb {
            location,
            defs: defs.to_vec(),
            uses: uses.to_vec(),
            entry,
        }
    }

    #[test]
    fn a_definition_reaches_the_reads_after_it() {
        // 0x1000 mov eax, 1       b8 01 00 00 00
        // 0x1005 add ecx, eax     01 c1
        // 0x1007 mov edx, eax     89 c2
        // 0x1009 ret              c3
        let bytes = [0xb8, 0x01, 0, 0, 0, 0x01, 0xc1, 0x89, 0xc2, 0xc3];
        let defuse = webs(&bytes);
        let expected = web(&[0x1000], &[0x1005, 0x1007, 0x1009], RAX, false);
        // From a use and from the definition alike.
        assert_eq!(defuse.value_at(0x1005, RAX), Some(expected.clone()));
        assert_eq!(defuse.value_at(0x1000, RAX), Some(expected.clone()));
        assert_eq!(expected.role(0x1000), Some(Role::Definition));
        assert_eq!(expected.role(0x1007), Some(Role::Use));
        assert_eq!(expected.role(0x1001), None);
        assert_eq!(
            expected.summary(0x1005, Bitness::Bits64),
            "rax at 0x1005: 1 definition, 3 uses"
        );
        // An instruction that does not touch the register has no value of
        // it.
        assert_eq!(defuse.value_at(0x1007, RCX), None);
        // `add ecx, eax` reads the entry value of rcx and writes a new one.
        assert_eq!(
            defuse.value_at(0x1005, RCX),
            Some(web(&[], &[0x1005], RCX, true))
        );
        assert_eq!(
            defuse.value_written(0x1005, RCX),
            Some(web(&[0x1005], &[], RCX, false))
        );
    }

    #[test]
    fn a_redefinition_starts_a_new_value() {
        // 0x1000 mov eax, 1       b8 01 00 00 00
        // 0x1005 mov ecx, eax     89 c1
        // 0x1007 mov eax, 2       b8 02 00 00 00
        // 0x100c mov edx, eax     89 c2
        // 0x100e ret              c3
        let bytes = [
            0xb8, 0x01, 0, 0, 0, 0x89, 0xc1, 0xb8, 0x02, 0, 0, 0, 0x89, 0xc2, 0xc3,
        ];
        let defuse = webs(&bytes);
        assert_eq!(
            defuse.value_at(0x1005, RAX),
            Some(web(&[0x1000], &[0x1005], RAX, false))
        );
        assert_eq!(
            defuse.value_at(0x100c, RAX),
            Some(web(&[0x1007], &[0x100c, 0x100e], RAX, false))
        );
    }

    #[test]
    fn two_definitions_that_reach_one_read_are_one_value() {
        // 0x1000 test edi, edi    85 ff
        // 0x1002 je 0x100b        74 07
        // 0x1004 mov eax, 1       b8 01 00 00 00
        // 0x1009 jmp 0x1010       eb 05
        // 0x100b mov eax, 2       b8 02 00 00 00
        // 0x1010 ret              c3
        let bytes = [
            0x85, 0xff, 0x74, 0x07, 0xb8, 0x01, 0, 0, 0, 0xeb, 0x05, 0xb8, 0x02, 0, 0, 0, 0xc3,
        ];
        let defuse = webs(&bytes);
        let joined = web(&[0x1004, 0x100b], &[0x1010], RAX, false);
        assert_eq!(defuse.value_at(0x1010, RAX), Some(joined.clone()));
        // Either arm's definition gives the whole web.
        assert_eq!(defuse.value_at(0x1004, RAX), Some(joined.clone()));
        assert_eq!(defuse.value_at(0x100b, RAX), Some(joined));
        // The parameter is the entry value; the flags are followed too.
        assert_eq!(
            defuse.value_at(0x1000, RDI),
            Some(web(&[], &[0x1000], RDI, true))
        );
        let zf = Location::parse("zf").unwrap();
        assert_eq!(
            defuse.value_at(0x1002, zf),
            Some(web(&[0x1000], &[0x1002], zf, false))
        );
    }

    #[test]
    fn a_32_bit_write_replaces_the_register_and_an_8_bit_one_keeps_it() {
        // 0x1000 mov eax, 1       b8 01 00 00 00
        // 0x1005 mov eax, 2       b8 02 00 00 00
        // 0x100a mov ecx, eax     89 c1
        // 0x100c ret              c3
        let whole = [0xb8, 0x01, 0, 0, 0, 0xb8, 0x02, 0, 0, 0, 0x89, 0xc1, 0xc3];
        let defuse = webs(&whole);
        assert_eq!(
            defuse.value_at(0x100a, RAX),
            Some(web(&[0x1005], &[0x100a, 0x100c], RAX, false))
        );
        assert_eq!(
            defuse.value_at(0x1000, RAX),
            Some(web(&[0x1000], &[], RAX, false)),
            "the first write is never read"
        );

        // 0x1000 mov eax, 1       b8 01 00 00 00
        // 0x1005 mov al, 2        b0 02
        // 0x1007 mov ecx, eax     89 c1
        // 0x1009 ret              c3
        let partial = [0xb8, 0x01, 0, 0, 0, 0xb0, 0x02, 0x89, 0xc1, 0xc3];
        let defuse = webs(&partial);
        let kept = web(&[0x1000, 0x1005], &[0x1005, 0x1007, 0x1009], RAX, false);
        assert_eq!(defuse.value_at(0x1007, RAX), Some(kept.clone()));
        assert_eq!(kept.role(0x1005), Some(Role::Both), "mov al reads the rest");
        let touch = defuse.touches(0x1005)[0];
        assert!(touch.reads && touch.writes && !touch.whole, "{touch:?}");
        assert_eq!(touch.width, 8);
    }

    #[test]
    fn a_call_reads_the_arguments_and_clobbers_the_caller_saved_registers() {
        // 0x1000 mov eax, 1       b8 01 00 00 00
        // 0x1005 mov edi, eax     89 c7
        // 0x1007 call 0x1000      e8 f4 ff ff ff
        // 0x100c mov ecx, eax     89 c1
        // 0x100e mov edx, edi     89 fa
        // 0x1010 ret              c3
        let bytes = [
            0xb8, 0x01, 0, 0, 0, 0x89, 0xc7, 0xe8, 0xf4, 0xff, 0xff, 0xff, 0x89, 0xc1, 0x89, 0xfa,
            0xc3,
        ];
        let defuse = webs(&bytes);
        // The value in eax before the call is read by the mov alone: rax
        // is no argument, and the call leaves its result there.
        assert_eq!(
            defuse.value_at(0x1000, RAX),
            Some(web(&[0x1000], &[0x1005], RAX, false))
        );
        assert_eq!(
            defuse.value_at(0x100c, RAX),
            Some(web(&[0x1007], &[0x100c, 0x1010], RAX, false))
        );
        // edi is an argument the call reads, and a register it clobbers.
        assert_eq!(
            defuse.value_at(0x1005, RDI),
            Some(web(&[0x1005], &[0x1007], RDI, false))
        );
        assert_eq!(
            defuse.value_at(0x100e, RDI),
            Some(web(&[0x1007], &[0x100e], RDI, false))
        );
        let call = defuse
            .touches(0x1007)
            .iter()
            .find(|touch| touch.location == RDI)
            .copied()
            .unwrap();
        assert!(call.implicit && call.reads && call.whole, "{call:?}");

        // Under Microsoft x64 rdi is the callee's to keep, and no
        // argument.
        let defuse = webs_with(&bytes, Abi::Win64);
        assert_eq!(
            defuse.value_at(0x100e, RDI),
            Some(web(&[0x1005], &[0x100e], RDI, false))
        );
    }

    #[test]
    fn a_parameter_is_the_entry_value() {
        // 0x1000 lea eax, [rdi+1] 8d 47 01
        // 0x1003 ret              c3
        let defuse = webs(&[0x8d, 0x47, 0x01, 0xc3]);
        let parameter = defuse.value_at(0x1000, RDI).unwrap();
        assert_eq!(parameter, web(&[], &[0x1000], RDI, true));
        assert_eq!(
            parameter.summary(0x1000, Bitness::Bits64),
            "rdi at 0x1000: the entry value, 1 use"
        );
    }

    #[test]
    fn a_read_write_in_a_loop_is_both_a_definition_and_a_use() {
        // 0x1000 xor eax, eax     31 c0
        // 0x1002 add eax, 1       83 c0 01
        // 0x1005 cmp eax, 10      83 f8 0a
        // 0x1008 jne 0x1002       75 f8
        // 0x100a ret              c3
        let bytes = [
            0x31, 0xc0, 0x83, 0xc0, 0x01, 0x83, 0xf8, 0x0a, 0x75, 0xf8, 0xc3,
        ];
        let defuse = webs(&bytes);
        let counter = web(&[0x1000, 0x1002], &[0x1002, 0x1005, 0x100a], RAX, false);
        assert_eq!(defuse.value_at(0x1005, RAX), Some(counter.clone()));
        assert_eq!(counter.role(0x1002), Some(Role::Both));
        assert_eq!(counter.role(0x1000), Some(Role::Definition));
        assert_eq!(
            counter.summary(0x1005, Bitness::Bits64),
            "rax at 0x1005: 2 definitions, 3 uses"
        );
    }

    #[test]
    fn a_read_write_outside_a_loop_reads_one_value_and_starts_another() {
        // 0x1000 mov eax, 1       b8 01 00 00 00
        // 0x1005 add eax, 2       83 c0 02
        // 0x1008 ret              c3
        let defuse = webs(&[0xb8, 0x01, 0, 0, 0, 0x83, 0xc0, 0x02, 0xc3]);
        assert_eq!(
            defuse.value_at(0x1005, RAX),
            Some(web(&[0x1000], &[0x1005], RAX, false))
        );
        assert_eq!(
            defuse.value_written(0x1005, RAX),
            Some(web(&[0x1005], &[0x1008], RAX, false))
        );
    }

    #[test]
    fn names_spell_the_whole_register_at_any_width() {
        for name in ["rax", "EAX", "ax", "al", "ah"] {
            assert_eq!(Location::parse(name), Some(RAX), "{name}");
        }
        for name in ["r9", "r9d", "r9w", "r9b", "r9l"] {
            assert_eq!(Location::parse(name), Some(Location::Register(9)), "{name}");
        }
        assert_eq!(Location::parse("dil"), Some(RDI));
        assert_eq!(Location::parse("xmm0"), None);
        assert_eq!(RAX.name(Bitness::Bits64), "rax");
        assert_eq!(RAX.name(Bitness::Bits32), "eax");
        assert_eq!(Location::parse("ZF").unwrap().name(Bitness::Bits64), "zf");
    }
}
