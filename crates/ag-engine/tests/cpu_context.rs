use ag_engine::cpu_context::{CpuContext, Flow, Operand, X86IcedContext};

const CODE: &[u8] = &[
    0x55,                                             // push rbp
    0x48, 0x89, 0xe5,                                 // mov rbp, rsp
    0x48, 0x8d, 0x05, 0x11, 0x22, 0x33, 0x44,         // lea rax, [rip+0x44332211]
    0xc3,                                             // ret
];

#[test]
fn decode_prologue_and_tail() {
    let mut ctx = X86IcedContext::default();
    let base = 0x101c380;
    let first = ctx.decode(&CODE[..9], base).expect("push rbp");
    assert_eq!(first.address, base);
    assert_eq!(first.length, 1);
    assert_eq!(first.mnemonic, iced_x86::Mnemonic::Push as u32);

    let mov = ctx.decode(&CODE[1..9], base + 1).expect("mov rbp, rsp");
    assert_eq!(mov.operands.len(), 2);
    assert!(matches!(mov.operands[0], Operand::Register(r) if r.class == 1 && r.index == 5));
    assert!(matches!(mov.operands[1], Operand::Register(r) if r.class == 1 && r.index == 4));

    let lea = ctx.decode(&CODE[4..], base + 4).expect("lea rip-rel");
    assert_eq!(lea.rip_relative_address, Some(base + 11 + 0x44332211));

    let ret = ctx.decode(&CODE[11..], base + 11).expect("ret");
    assert_eq!(ret.flow, Flow::Return);

    let mut ctx2 = X86IcedContext::default();
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx2, CODE, base).unwrap();
    assert_eq!(dys.instructions.len(), 4);
    assert!(dys.instruction_at(base + 4).is_some());
}
