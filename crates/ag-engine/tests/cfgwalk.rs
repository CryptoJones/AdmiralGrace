use ag_engine::cfgwalk::resolve_branches;
use ag_engine::cpu_context::X86IcedContext;
use ag_engine::pipeline::Disasm;

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
