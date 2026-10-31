use ag_engine::cfgwalk::{resolve_branches, resolve_branches_among, Entries, TableHint};
use ag_engine::cpu_context::X86IcedContext;
use ag_engine::pipeline::Disasm;
use ag_engine::TailCall;

// 0x1000: test eax,eax      ; 85 c0
// 0x1002: je  x             ; 74 0c   -> 0x1010
// 0x1004: push rbp          ; 55
// 0x1005: pop  rbp          ; 5d
// 0x1006: ret               ; c3
// 0x1010: call 0x1000       ; e8 eb ff ff ff
// 0x1015: ret               ; c3
const LOOP: &[u8] = &[
    0x85, 0xc0, 0x74, 0x0c, 0x55, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xe8, 0xeb, 0xff, 0xff, 0xff, 0xc3,
];

#[test]
fn cfg_loop_with_call() {
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, LOOP, 0x1000).unwrap();
    let cfg = resolve_branches(&d, 0x1000);
    assert_eq!(
        cfg.blocks.len(),
        4,
        "entry, branch-arm, loop-head, call-return"
    );
    assert!(cfg.call_sites.contains(&0x1010), "call site recorded");
    let entry = cfg
        .blocks
        .iter()
        .find(|b| b.from == 0x1000)
        .expect("entry block");
    assert_eq!(entry.to, 0x1004);
    assert!(entry.successor_addresses.contains(&0x1010));
    assert!(entry.successor_addresses.contains(&0x1004));
    assert!(
        cfg.blocks.iter().any(|b| b.from == 0x1004),
        "branch-arm block walked"
    );
    assert!(cfg.blocks.iter().any(|b| b.from == 0x1015));
    assert!(cfg.index_by_address.contains_key(&0x1010));
}

#[test]
fn a_trap_ends_its_block_and_a_syscall_does_not() {
    use ag_engine::cpu_context::X86IcedContext;
    // syscall ; ud2 ; ret  — the ret after ud2 is unreachable by fall-through.
    let bytes = [0x0f, 0x05, 0x0f, 0x0b, 0xc3];
    let mut ctx = X86IcedContext::default();
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();
    let cfg = ag_engine::cfgwalk::resolve_branches(&dys, 0x1000);
    assert_eq!(
        cfg.blocks.len(),
        1,
        "syscall falls through, ud2 ends the block"
    );
    assert_eq!(cfg.blocks[0].from, 0x1000);
    assert_eq!(cfg.blocks[0].to, 0x1004);
    assert!(cfg.blocks[0].successor_addresses.is_empty());
}

#[test]
fn a_halt_ends_its_block_with_no_successor() {
    use ag_engine::cpu_context::X86IcedContext;
    // hlt ; nop ; ret  — the code after hlt is unreachable by fall-through.
    let bytes = [0xf4, 0x90, 0xc3];
    let mut ctx = X86IcedContext::default();
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();
    let cfg = ag_engine::cfgwalk::resolve_branches(&dys, 0x1000);
    assert_eq!(cfg.blocks.len(), 1, "hlt ends the block: {:?}", cfg.blocks);
    assert_eq!(cfg.blocks[0].from, 0x1000);
    assert_eq!(cfg.blocks[0].to, 0x1001);
    assert!(cfg.blocks[0].successor_addresses.is_empty());
}

#[test]
fn xbegin_forks_to_its_abort_handler_and_the_transaction() {
    use ag_engine::cpu_context::X86IcedContext;
    // xbegin +1 ; nop ; ret  — abort handler is the ret at 0x1007.
    let bytes = [0xc7, 0xf8, 0x01, 0x00, 0x00, 0x00, 0x90, 0xc3];
    let mut ctx = X86IcedContext::default();
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();
    let cfg = ag_engine::cfgwalk::resolve_branches(&dys, 0x1000);
    let entry = &cfg.blocks[cfg.index_by_address[&0x1000] as usize];
    assert_eq!(entry.to, 0x1006);
    assert_eq!(entry.successor_addresses, vec![0x1007, 0x1006]);
}

fn cfg_of(bytes: &[u8]) -> ag_engine::ProcedureCfg {
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, bytes, 0x1000).unwrap();
    let cfg = resolve_branches(&d, 0x1000);
    assert_well_formed(&cfg);
    cfg
}

/// No two blocks overlap, every successor is a block start, no successor is
/// listed twice, and the address index agrees with the blocks.
fn assert_well_formed(cfg: &ag_engine::ProcedureCfg) {
    let mut sorted: Vec<&ag_engine::BasicBlock> = cfg.blocks.iter().collect();
    sorted.sort_by_key(|b| b.from);
    for pair in sorted.windows(2) {
        assert!(
            pair[0].to <= pair[1].from,
            "blocks overlap: [{:#x},{:#x}) and [{:#x},{:#x})",
            pair[0].from,
            pair[0].to,
            pair[1].from,
            pair[1].to
        );
    }
    for b in &cfg.blocks {
        assert!(b.from < b.to, "empty block at {:#x}", b.from);
        let mut seen = std::collections::BTreeSet::new();
        for &s in &b.successor_addresses {
            assert!(
                cfg.index_by_address.contains_key(&s),
                "dangling successor {s:#x}"
            );
            assert!(seen.insert(s), "duplicate successor {s:#x}");
        }
    }
    assert_eq!(cfg.index_by_address.len(), cfg.blocks.len());
}

fn block(cfg: &ag_engine::ProcedureCfg, from: u64) -> &ag_engine::BasicBlock {
    &cfg.blocks[cfg.index_by_address[&from] as usize]
}

#[test]
fn an_if_diamond_splits_at_the_join() {
    // 0x1000 je 0x1004 ; 0x1002 nop ; 0x1003 nop ; 0x1004 ret
    let cfg = cfg_of(&[0x74, 0x02, 0x90, 0x90, 0xc3]);
    assert_eq!(cfg.blocks.len(), 3);
    assert_eq!(block(&cfg, 0x1000).to, 0x1002);
    assert_eq!(
        block(&cfg, 0x1000).successor_addresses,
        vec![0x1004, 0x1002]
    );
    assert_eq!(block(&cfg, 0x1002).to, 0x1004);
    assert_eq!(block(&cfg, 0x1002).successor_addresses, vec![0x1004]);
    assert_eq!(block(&cfg, 0x1004).to, 0x1005);
    assert!(block(&cfg, 0x1004).successor_addresses.is_empty());
}

#[test]
fn a_backward_branch_into_a_block_splits_it() {
    // 0x1000 xor eax,eax ; 0x1002 inc eax ; 0x1004 cmp eax,10 ; 0x1007 jne 0x1002 ; 0x1009 ret
    let cfg = cfg_of(&[0x31, 0xc0, 0xff, 0xc0, 0x83, 0xf8, 0x0a, 0x75, 0xf9, 0xc3]);
    assert_eq!(cfg.blocks.len(), 3);
    assert_eq!(block(&cfg, 0x1000).to, 0x1002);
    assert_eq!(block(&cfg, 0x1000).successor_addresses, vec![0x1002]);
    assert_eq!(block(&cfg, 0x1002).to, 0x1009);
    assert_eq!(
        block(&cfg, 0x1002).successor_addresses,
        vec![0x1002, 0x1009]
    );
    assert_eq!(block(&cfg, 0x1009).to, 0x100a);
}

#[test]
fn a_jump_target_is_always_scheduled() {
    // 0x1000 jmp 0x1002 ; 0x1002 ret
    let cfg = cfg_of(&[0xeb, 0x00, 0xc3]);
    assert_eq!(cfg.blocks.len(), 2);
    assert_eq!(block(&cfg, 0x1000).successor_addresses, vec![0x1002]);
}

#[test]
fn an_indirect_call_keeps_its_continuation() {
    // 0x1000 call rax ; 0x1002 ret
    let cfg = cfg_of(&[0xff, 0xd0, 0xc3]);
    assert_eq!(cfg.blocks.len(), 2);
    assert_eq!(cfg.call_sites, vec![0x1000]);
    assert!(cfg.call_targets.is_empty());
    assert_eq!(block(&cfg, 0x1000).to, 0x1002);
    assert_eq!(block(&cfg, 0x1000).successor_addresses, vec![0x1002]);
}

#[test]
fn a_callee_is_recorded_but_not_walked() {
    // 0x1000 call 0x1006 ; 0x1005 ret ; 0x1006 ret
    let cfg = cfg_of(&[0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3]);
    assert_eq!(
        cfg.blocks.len(),
        2,
        "the callee at 0x1006 is not part of this procedure"
    );
    assert!(!cfg.index_by_address.contains_key(&0x1006));
    assert_eq!(cfg.call_sites, vec![0x1000]);
    assert_eq!(cfg.call_targets, vec![0x1006]);
    assert_eq!(block(&cfg, 0x1000).successor_addresses, vec![0x1005]);
}

#[test]
fn a_branch_to_the_next_instruction_lists_one_successor() {
    // 0x1000 je 0x1002 ; 0x1002 ret
    let cfg = cfg_of(&[0x74, 0x00, 0xc3]);
    assert_eq!(block(&cfg, 0x1000).successor_addresses, vec![0x1002]);
}

#[test]
fn an_interrupt_falls_through() {
    // 0x1000 int 0x80 ; 0x1002 ret
    let cfg = cfg_of(&[0xcd, 0x80, 0xc3]);
    assert_eq!(cfg.blocks.len(), 1);
    assert_eq!(block(&cfg, 0x1000).to, 0x1003);
}

#[test]
fn the_loop_with_a_call_is_well_formed() {
    let cfg = cfg_of(LOOP);
    assert_eq!(cfg.call_targets, vec![0x1000]);
    assert_eq!(
        block(&cfg, 0x1000).successor_addresses,
        vec![0x1010, 0x1004]
    );
}

#[test]
fn an_invalid_byte_ends_the_block_and_code_after_it_is_still_a_target() {
    // 0x1000 jmp 0x1004 ; 0x1002 0x06 (invalid) ; 0x1003 nop ; 0x1004 ret
    let cfg = cfg_of(&[0xeb, 0x02, 0x06, 0x90, 0xc3]);
    assert_eq!(cfg.blocks.len(), 2, "the entry and the jump target");
    assert_eq!(block(&cfg, 0x1000).successor_addresses, vec![0x1004]);
    assert!(
        !cfg.index_by_address.contains_key(&0x1002),
        "the data byte is not a block"
    );
}

// `main` of the 32-bit fixture (crates/ag-image/tests/fixtures/sample32.elf),
// at 0x804900d. A loop that calls `add` three times, then reads `counter`
// and `greeting` through absolute memory operands.
//
// 0x804900d: push ebp; mov ebp,esp; sub esp,0x10; mov [ebp-4],0; mov [ebp-8],0
// 0x8049021: jmp 0x8049038
// 0x8049023: push [ebp-8]; push [ebp-4]; call 0x8049000 (add)
// 0x804902e: add esp,8; mov [ebp-4],eax; add [ebp-8],1
// 0x8049038: cmp [ebp-8],2; jle 0x8049023
// 0x804903e: mov edx,[0x804b008]; ...; mov eax,[0x804b00c]; ...; leave; ret
const MAIN32: &[u8] = &[
    0x55, 0x89, 0xe5, 0x83, 0xec, 0x10, 0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf8,
    0x00, 0x00, 0x00, 0x00, 0xeb, 0x15, 0xff, 0x75, 0xf8, 0xff, 0x75, 0xfc, 0xe8, 0xd2, 0xff, 0xff,
    0xff, 0x83, 0xc4, 0x08, 0x89, 0x45, 0xfc, 0x83, 0x45, 0xf8, 0x01, 0x83, 0x7d, 0xf8, 0x02, 0x7e,
    0xe5, 0x8b, 0x15, 0x08, 0xb0, 0x04, 0x08, 0x8b, 0x45, 0xfc, 0x01, 0xc2, 0xa1, 0x0c, 0xb0, 0x04,
    0x08, 0x0f, 0xb6, 0x00, 0x0f, 0xbe, 0xc0, 0x01, 0xd0, 0xc9, 0xc3,
];

#[test]
fn the_walk_of_32_bit_code_finds_its_loop_and_its_call() {
    let mut ctx = X86IcedContext::new(ag_engine::Bitness::Bits32);
    let d = Disasm::decode(&mut ctx, MAIN32, 0x804900d).unwrap();
    let cfg = resolve_branches(&d, 0x804900d);

    let blocks: Vec<(u64, u64, Vec<u64>)> = cfg
        .blocks
        .iter()
        .map(|b| (b.from, b.to, b.successor_addresses.clone()))
        .collect();
    assert_eq!(
        blocks,
        vec![
            (0x804900d, 0x8049023, vec![0x8049038]),
            (0x8049023, 0x804902e, vec![0x804902e]),
            (0x804902e, 0x8049038, vec![0x8049038]),
            (0x8049038, 0x804903e, vec![0x8049023, 0x804903e]),
            (0x804903e, 0x8049058, vec![]),
        ],
        "the prologue, the body of the loop, the return from add, the test, the tail"
    );
    assert_eq!(cfg.call_sites, vec![0x8049029]);
    assert_eq!(
        cfg.call_targets,
        vec![0x8049000],
        "the call to add is recorded"
    );

    // The data the tail reads is named by the absolute operands.
    let pointers: Vec<u64> = d
        .instructions
        .iter()
        .filter_map(|i| i.memory_address())
        .collect();
    assert_eq!(pointers, vec![0x804b008, 0x804b00c]);
}

/// The functions and import slots an image would know.
struct Known {
    functions: &'static [u64],
    slots: &'static [u64],
}

impl Entries for Known {
    fn is_function(&self, address: u64) -> bool {
        self.functions.contains(&address)
    }

    fn is_import_slot(&self, slot: u64) -> bool {
        self.slots.contains(&slot)
    }
}

// 0x1000: jmp 0x1010   ; eb 0e
// 0x1002: ret          ; c3  (not reached)
// 0x1010: ret          ; c3
const JUMP_OUT: &[u8] = &[
    0xeb, 0x0e, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xc3,
];

#[test]
fn a_jmp_to_the_entry_of_another_function_is_a_tail_call_and_not_an_edge() {
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, JUMP_OUT, 0x1000).unwrap();

    // Told that 0x1010 is a function, the walk stops at the jump: one
    // block, no successor, the tail call recorded.
    let known = Known {
        functions: &[0x1010],
        slots: &[],
    };
    let cfg = resolve_branches_among(&d, 0x1000, &known);
    assert_well_formed(&cfg);
    assert_eq!(cfg.blocks.len(), 1, "{cfg:?}");
    assert_eq!((cfg.blocks[0].from, cfg.blocks[0].to), (0x1000, 0x1002));
    assert!(cfg.blocks[0].successor_addresses.is_empty(), "{cfg:?}");
    assert_eq!(
        cfg.tail_calls,
        vec![TailCall {
            site: 0x1000,
            target: 0x1010
        }]
    );
    assert!(cfg.call_sites.is_empty(), "a tail call is not a call site");

    // Told nothing, the walk follows the jump as before.
    let cfg = resolve_branches(&d, 0x1000);
    assert_well_formed(&cfg);
    assert_eq!(cfg.blocks.len(), 2, "{cfg:?}");
    assert_eq!(cfg.blocks[0].successor_addresses, vec![0x1010]);
    assert!(cfg.tail_calls.is_empty());
}

#[test]
fn a_jmp_to_the_procedure_s_own_entry_is_a_loop_even_when_the_entry_is_a_function() {
    // 0x1000: jmp 0x1000 ; eb fe
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, &[0xeb, 0xfe], 0x1000).unwrap();
    let known = Known {
        functions: &[0x1000],
        slots: &[],
    };
    let cfg = resolve_branches_among(&d, 0x1000, &known);
    assert_well_formed(&cfg);
    assert_eq!(cfg.blocks.len(), 1);
    assert_eq!(cfg.blocks[0].successor_addresses, vec![0x1000]);
    assert!(cfg.tail_calls.is_empty(), "{cfg:?}");
}

#[test]
fn a_jmp_through_an_import_slot_is_a_tail_call_to_the_slot() {
    // 0x1000: jmp [rip+0x2ffa] ; ff 25 fa 2f 00 00 -> slot 0x4000
    // 0x1006: ret              ; c3  (not reached)
    let bytes = [0xff, 0x25, 0xfa, 0x2f, 0x00, 0x00, 0xc3];
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();

    let known = Known {
        functions: &[],
        slots: &[0x4000],
    };
    let cfg = resolve_branches_among(&d, 0x1000, &known);
    assert_well_formed(&cfg);
    assert_eq!(cfg.blocks.len(), 1, "{cfg:?}");
    assert!(cfg.blocks[0].successor_addresses.is_empty());
    assert_eq!(
        cfg.tail_calls,
        vec![TailCall {
            site: 0x1000,
            target: 0x4000
        }]
    );

    // A slot the image does not name is an indirect jump as before: the
    // block ends, and nothing is recorded.
    let cfg = resolve_branches(&d, 0x1000);
    assert_eq!(cfg.blocks.len(), 1);
    assert!(cfg.blocks[0].successor_addresses.is_empty());
    assert!(cfg.tail_calls.is_empty());
}

/// A `switch` of six cases compiled without position independence, as
/// `gcc -O1 -fno-pic -no-pie` lays it out: the index is bounded by a
/// compare, zero-extended, and jumps through an absolute table of 8-byte
/// entries.
///
/// ```text
/// 401000: cmp    edi,0x5
/// 401003: ja     40102d
/// 401005: mov    edi,edi
/// 401007: jmp    QWORD PTR [rdi*8+0x402000]
/// 40100e: mov    eax,0xa     ; ret        case 0
/// 401014: mov    eax,[rip+…] ; ret        case 2
/// 40101b: mov    eax,0x28    ; ret        case 3
/// 401021: mov    eax,0x32    ; ret        case 4
/// 401027: mov    eax,0x3c    ; ret        case 5
/// 40102d: mov    eax,-1      ; ret        default
/// 401033: mov    eax,0x14    ; ret        case 1
/// ```
const SWITCH_ABSOLUTE: &[u8] = &[
    0x83, 0xff, 0x05, 0x77, 0x28, 0x89, 0xff, 0xff, 0x24, 0xfd, 0x00, 0x20, 0x40, 0x00, 0xb8, 0x0a,
    0x00, 0x00, 0x00, 0xc3, 0x8b, 0x05, 0x16, 0x20, 0x00, 0x00, 0xc3, 0xb8, 0x28, 0x00, 0x00, 0x00,
    0xc3, 0xb8, 0x32, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0xff, 0xff,
    0xff, 0xff, 0xc3, 0xb8, 0x14, 0x00, 0x00, 0x00, 0xc3,
];

/// The same `switch` compiled position-independent: the table holds
/// 4-byte offsets from its own address, read through `lea`/`movsxd`/`add`.
///
/// ```text
/// 1000: cmp    edi,0x5
/// 1003: ja     1036
/// 1005: mov    edi,edi
/// 1007: lea    rdx,[rip+0xff2]          ; 2000
/// 100e: movsxd rax,DWORD PTR [rdx+rdi*4]
/// 1012: add    rax,rdx
/// 1015: jmp    rax
/// 1017: mov eax,0xa ; ret                 case 0
/// 101d: mov eax,[rip+…] ; ret             case 2
/// 1024: mov eax,0x28 ; ret                case 3
/// 102a: mov eax,0x32 ; ret                case 4
/// 1030: mov eax,0x3c ; ret                case 5
/// 1036: mov eax,-1 ; ret                  default
/// 103c: mov eax,0x14 ; ret                case 1
/// ```
const SWITCH_RELATIVE: &[u8] = &[
    0x83, 0xff, 0x05, 0x77, 0x31, 0x89, 0xff, 0x48, 0x8d, 0x15, 0xf2, 0x0f, 0x00, 0x00, 0x48, 0x63,
    0x04, 0xba, 0x48, 0x01, 0xd0, 0xff, 0xe0, 0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3, 0x8b, 0x05, 0xdd,
    0x2f, 0x00, 0x00, 0xc3, 0xb8, 0x28, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x32, 0x00, 0x00, 0x00, 0xc3,
    0xb8, 0x3c, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3, 0xb8, 0x14, 0x00, 0x00,
    0x00, 0xc3,
];

/// An image that knows a jump table's bytes, and nothing else.
struct Table {
    at: u64,
    entries: Vec<u64>,
    width: u8,
    hint: Option<TableHint>,
}

impl Entries for Table {
    fn is_function(&self, _address: u64) -> bool {
        false
    }
    fn is_import_slot(&self, _slot: u64) -> bool {
        false
    }
    fn table_entry(&self, address: u64, width: u8) -> Option<u64> {
        if width != self.width || address < self.at {
            return None;
        }
        let offset = address - self.at;
        if !offset.is_multiple_of(width as u64) {
            return None;
        }
        self.entries.get((offset / width as u64) as usize).copied()
    }
    fn table_hint(&self, _site: u64) -> Option<TableHint> {
        self.hint
    }
}

#[test]
fn a_jump_through_an_absolute_table_goes_to_every_case() {
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, SWITCH_ABSOLUTE, 0x401000).unwrap();
    let table = Table {
        at: 0x402000,
        entries: vec![0x40100e, 0x401033, 0x401014, 0x40101b, 0x401021, 0x401027],
        width: 8,
        hint: None,
    };
    let cfg = resolve_branches_among(&d, 0x401000, &table);

    let jump = cfg
        .blocks
        .iter()
        .find(|b| b.from == 0x401005)
        .expect("the block that jumps through the table");
    assert_eq!(
        jump.successor_addresses,
        [0x40100e, 0x401033, 0x401014, 0x40101b, 0x401021, 0x401027],
        "every case, in table order"
    );
    assert!(
        cfg.blocks.iter().any(|b| b.from == 0x401033),
        "the case only the table reaches is walked"
    );
    assert_eq!(cfg.jump_tables.len(), 1);
    let recovered = &cfg.jump_tables[0];
    assert_eq!(recovered.site, 0x401007);
    assert_eq!(recovered.table, 0x402000);
    assert_eq!(recovered.width, 8);
    assert!(!recovered.relative);
    assert_eq!(recovered.base, 0);
    assert_eq!(recovered.targets.len(), 6, "cmp edi,5; ja — six cases");
    let index = recovered.index.expect("the index register");
    assert_eq!(index.index, 7, "rdi");
    assert_eq!(
        recovered.cases(),
        vec![
            (vec![0], 0x40100e),
            (vec![1], 0x401033),
            (vec![2], 0x401014),
            (vec![3], 0x40101b),
            (vec![4], 0x401021),
            (vec![5], 0x401027),
        ]
    );
    assert!(cfg.tail_calls.is_empty(), "a table jump is not a tail call");
}

#[test]
fn a_jump_through_a_relative_table_adds_each_offset_to_the_table() {
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, SWITCH_RELATIVE, 0x1000).unwrap();
    let offsets: [i32; 6] =
        [0x1017, 0x103c, 0x101d, 0x1024, 0x102a, 0x1030].map(|target: i32| target - 0x2000);
    let table = Table {
        at: 0x2000,
        entries: offsets.iter().map(|o| *o as u32 as u64).collect(),
        width: 4,
        hint: None,
    };
    let cfg = resolve_branches_among(&d, 0x1000, &table);

    let jump = cfg
        .blocks
        .iter()
        .find(|b| b.from == 0x1005)
        .expect("the block that jumps through the table");
    assert_eq!(
        jump.successor_addresses,
        [0x1017, 0x103c, 0x101d, 0x1024, 0x102a, 0x1030]
    );
    let recovered = &cfg.jump_tables[0];
    assert_eq!(recovered.site, 0x1015);
    assert_eq!(recovered.table, 0x2000);
    assert_eq!(recovered.width, 4);
    assert!(recovered.relative);
    assert_eq!(
        recovered.index.map(|r| r.index),
        Some(7),
        "rdi indexes the table"
    );
}

#[test]
fn a_table_the_walk_cannot_read_leaves_the_jump_unresolved() {
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, SWITCH_ABSOLUTE, 0x401000).unwrap();
    // No bytes behind the table: nothing to recover, as before.
    let cfg = resolve_branches(&d, 0x401000);
    let jump = cfg.blocks.iter().find(|b| b.from == 0x401005).unwrap();
    assert!(jump.successor_addresses.is_empty());
    assert!(cfg.jump_tables.is_empty());

    // A table whose entries point outside the code stops at the first
    // such entry; one with no good entry is no table.
    let bad = Table {
        at: 0x402000,
        entries: vec![0x40100e, 0x401033, 0xdead_beef, 0x40101b],
        width: 8,
        hint: None,
    };
    let cfg = resolve_branches_among(&d, 0x401000, &bad);
    assert_eq!(cfg.jump_tables[0].targets, [0x40100e, 0x401033]);
    let none = Table {
        at: 0x402000,
        entries: vec![0xdead_beef],
        width: 8,
        hint: None,
    };
    let cfg = resolve_branches_among(&d, 0x401000, &none);
    assert!(cfg.jump_tables.is_empty());
}

#[test]
fn the_analysts_hint_stands_in_for_the_table_and_the_count() {
    // A jump through a register the code before it does not explain: only
    // the hint says where the table is.
    // 1000: jmp rax ; 1002: ret ; 1003: ret
    let bytes = [0xff, 0xe0, 0xc3, 0xc3];
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();
    let table = Table {
        at: 0x3000,
        entries: vec![0x1002, 0x1003, 0x1002],
        width: 8,
        hint: Some(TableHint {
            table: 0x3000,
            width: 8,
            count: 3,
            relative: false,
        }),
    };
    let cfg = resolve_branches_among(&d, 0x1000, &table);
    let jump = cfg.blocks.iter().find(|b| b.from == 0x1000).unwrap();
    assert_eq!(
        jump.successor_addresses,
        [0x1002, 0x1003],
        "each place once"
    );
    let recovered = &cfg.jump_tables[0];
    assert_eq!(recovered.targets, [0x1002, 0x1003, 0x1002]);
    assert_eq!(
        recovered.cases(),
        vec![(vec![0, 2], 0x1002), (vec![1], 0x1003)],
        "two cases share a place"
    );
    assert!(
        recovered.index.is_none(),
        "the code did not say which register"
    );

    // With the bytes but no hint, the same jump stays unresolved.
    let plain = Table {
        hint: None,
        ..table
    };
    let cfg = resolve_branches_among(&d, 0x1000, &plain);
    assert!(cfg.jump_tables.is_empty());
}

/// Two routines that share a tail, and a third nothing names: the
/// `boundaries.elf` fixture's code.
///
/// ```text
/// 401000: mov eax,1 ; jmp 40100c        main
/// 401007: mov eax,2                     helper
/// 40100c: ret                           shared (no function symbol)
/// 40100d: nop dword [rax]               padding
/// 401010: mov eax,3 ; ret               an unnamed routine
/// ```
const SHARED_TAIL: &[u8] = &[
    0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3, 0x0f, 0x1f, 0x00,
    0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3,
];

/// An image of two functions whose branches end at the next function.
struct Bounded {
    functions: Vec<u64>,
    ends: bool,
}

impl Entries for Bounded {
    fn is_function(&self, address: u64) -> bool {
        self.functions.contains(&address)
    }
    fn is_import_slot(&self, _slot: u64) -> bool {
        false
    }
    fn branch_leaves(&self, entry: u64, target: u64) -> bool {
        if !self.ends {
            return false;
        }
        let next = self.functions.iter().filter(|f| **f > entry).min().copied();
        target < entry || next.is_some_and(|next| target >= next)
    }
}

#[test]
fn a_branch_past_the_next_function_ends_the_procedure_when_told_to() {
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, SHARED_TAIL, 0x401000).unwrap();
    let functions = vec![0x401000, 0x401007];

    // By default the jump into helper's tail is main's own block.
    let loose = Bounded {
        functions: functions.clone(),
        ends: false,
    };
    let cfg = resolve_branches_among(&d, 0x401000, &loose);
    assert_eq!(cfg.blocks.len(), 2);
    assert!(cfg.tail_calls.is_empty());
    assert!(cfg.blocks.iter().any(|b| b.from == 0x40100c));

    // Told that branches end procedures, the jump is a tail call to the
    // shared ret, and main is its one block.
    let bounded = Bounded {
        functions,
        ends: true,
    };
    let cfg = resolve_branches_among(&d, 0x401000, &bounded);
    assert_eq!(cfg.blocks.len(), 1);
    assert_eq!(cfg.blocks[0].to, 0x401007);
    assert!(cfg.blocks[0].successor_addresses.is_empty());
    assert_eq!(
        cfg.tail_calls,
        [TailCall {
            site: 0x401005,
            target: 0x40100c
        }]
    );

    // helper's own jump-free body still reaches the shared ret: it is
    // inside helper's range.
    let cfg = resolve_branches_among(&d, 0x401007, &bounded);
    assert_eq!(cfg.blocks.len(), 1);
    assert_eq!(cfg.blocks[0].to, 0x40100d);
}

#[test]
fn a_conditional_branch_past_the_next_function_leaves_on_the_taken_side_only() {
    // 401000: je 401007 (into helper) ; 401002: ret ; ... helper at 401007
    let bytes = [
        0x74, 0x05, 0xc3, 0x90, 0x90, 0x90, 0x90, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,
    ];
    let mut ctx = X86IcedContext::default();
    let d = Disasm::decode(&mut ctx, &bytes, 0x401000).unwrap();
    let bounded = Bounded {
        functions: vec![0x401000, 0x401007],
        ends: true,
    };
    let cfg = resolve_branches_among(&d, 0x401000, &bounded);
    let entry = cfg.blocks.iter().find(|b| b.from == 0x401000).unwrap();
    assert_eq!(
        entry.successor_addresses,
        [0x401002],
        "only the fall-through"
    );
    assert_eq!(
        cfg.tail_calls,
        [TailCall {
            site: 0x401000,
            target: 0x401007
        }]
    );
}

/// Functions the image knows, and the ones among them that never return.
struct Dying {
    functions: &'static [u64],
    noreturn: &'static [u64],
}

impl Entries for Dying {
    fn is_function(&self, address: u64) -> bool {
        self.functions.contains(&address)
    }

    fn is_import_slot(&self, _slot: u64) -> bool {
        false
    }

    fn returns(&self, callee: u64) -> bool {
        !self.noreturn.contains(&callee)
    }
}

// 0x1000: call 0x1010   ; e8 0b 00 00 00
// 0x1005: ret           ; c3  (not reached: 0x1010 never returns)
// 0x1006: ret           ; c3  (another function's, reached by nothing)
// 0x1010: hlt           ; f4
#[test]
fn a_call_to_a_function_that_never_returns_ends_the_block_without_a_successor() {
    let bytes = [0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3, 0xc3];
    let mut ctx = X86IcedContext::default();
    let disasm = Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();
    let cfg = resolve_branches_among(
        &disasm,
        0x1000,
        &Dying {
            functions: &[0x1000, 0x1010],
            noreturn: &[0x1010],
        },
    );
    assert_eq!(cfg.blocks.len(), 1, "{cfg:?}");
    assert_eq!(cfg.blocks[0].to, 0x1005);
    assert!(cfg.blocks[0].successor_addresses.is_empty());
    assert_eq!(cfg.call_targets, vec![0x1010]);
    // The same call to a function that returns falls through to the ret.
    let cfg = resolve_branches_among(
        &disasm,
        0x1000,
        &Dying {
            functions: &[0x1000, 0x1010],
            noreturn: &[],
        },
    );
    assert_eq!(cfg.blocks.len(), 2, "{cfg:?}");
}

// 0x1000: mov eax, 60    ; b8 3c 00 00 00
// 0x1005: syscall        ; 0f 05
// 0x1007: ret            ; c3   — the next function's entry
#[test]
fn code_does_not_run_into_the_next_functions_entry() {
    let bytes = [0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3];
    let mut ctx = X86IcedContext::default();
    let disasm = Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();
    let cfg = resolve_branches_among(
        &disasm,
        0x1000,
        &Dying {
            functions: &[0x1000, 0x1007],
            noreturn: &[],
        },
    );
    assert_eq!(cfg.blocks.len(), 1, "{cfg:?}");
    assert_eq!(cfg.blocks[0].to, 0x1007);
    assert!(cfg.blocks[0].successor_addresses.is_empty());
    // After the system call nothing fell through: not a tail call.
    assert!(cfg.tail_calls.is_empty(), "{cfg:?}");
}

// 0x1000: mov eax, 1     ; b8 01 00 00 00   — outer, which falls into
// 0x1005: ret            ; c3               — inner, a function of its own
#[test]
fn code_that_falls_into_the_next_function_tail_calls_it() {
    let bytes = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
    let mut ctx = X86IcedContext::default();
    let disasm = Disasm::decode(&mut ctx, &bytes, 0x1000).unwrap();
    let cfg = resolve_branches_among(
        &disasm,
        0x1000,
        &Dying {
            functions: &[0x1000, 0x1005],
            noreturn: &[],
        },
    );
    assert_eq!(cfg.blocks.len(), 1, "{cfg:?}");
    assert_eq!(cfg.blocks[0].to, 0x1005);
    assert!(cfg.blocks[0].successor_addresses.is_empty());
    assert_eq!(cfg.tail_calls.len(), 1, "{cfg:?}");
    assert_eq!(cfg.tail_calls[0].site, 0x1000);
    assert_eq!(cfg.tail_calls[0].target, 0x1005);
}
