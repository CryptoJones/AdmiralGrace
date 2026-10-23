use ag_engine::cpu_context::{CpuContext, Flow, Operand, X86IcedContext};

const CODE: &[u8] = &[
    0x55, // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0x48, 0x8d, 0x05, 0x11, 0x22, 0x33, 0x44, // lea rax, [rip+0x44332211]
    0xc3, // ret
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

#[test]
fn ud2_is_a_trap_and_decoding_continues_past_it() {
    // ud2 ; ret — real x86-64 code carries ud2 after every noreturn call.
    let bytes = [0x0f, 0x0b, 0xc3];
    let mut ctx = X86IcedContext::default();
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx, &bytes, 0x1000)
        .expect("a trap must not abort the segment");
    assert_eq!(dys.instructions.len(), 2);
    assert_eq!(dys.instructions[0].flow, Flow::Trap);
    assert_eq!(dys.instructions[0].length, 2);
    assert_eq!(dys.instructions[1].flow, Flow::Return);
}

#[test]
fn syscall_and_sysenter_have_their_own_flow() {
    let mut ctx = X86IcedContext::default();
    let syscall = ctx.decode(&[0x0f, 0x05], 0x1000).expect("syscall");
    assert_eq!(syscall.flow, Flow::Syscall);
    let sysenter = ctx.decode(&[0x0f, 0x34], 0x1000).expect("sysenter");
    assert_eq!(sysenter.flow, Flow::Syscall);
    // int 0x80 stays a software interrupt.
    let int80 = ctx.decode(&[0xcd, 0x80], 0x1000).expect("int 0x80");
    assert_eq!(int80.flow, Flow::Interrupt);
}

#[test]
fn xbegin_carries_its_abort_handler_and_xend_falls_through() {
    let mut ctx = X86IcedContext::default();
    // xbegin rel32 = +0x10 from the end of the 6-byte instruction.
    let xbegin = ctx
        .decode(&[0xc7, 0xf8, 0x10, 0x00, 0x00, 0x00], 0x1000)
        .expect("xbegin");
    assert_eq!(xbegin.flow, Flow::Xbegin(0x1016));
    let xend = ctx.decode(&[0x0f, 0x01, 0xd5], 0x1000).expect("xend");
    assert_eq!(xend.flow, Flow::Next);
    let xabort = ctx.decode(&[0xc6, 0xf8, 0x00], 0x1000).expect("xabort");
    assert_eq!(xabort.flow, Flow::Next);
}
