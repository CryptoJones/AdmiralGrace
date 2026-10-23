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
