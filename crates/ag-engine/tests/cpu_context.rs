use ag_engine::cpu_context::{CpuContext, Flow, Operand, X86IcedContext, RC_GPR, RC_SEG, RC_VEC};
use ag_engine::register::{RegisterId, RegisterSet};

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
    assert_eq!(
        mov.operands[0],
        Operand::Register(RegisterId::new(RC_GPR, 5, 64))
    );
    assert_eq!(
        mov.operands[1],
        Operand::Register(RegisterId::new(RC_GPR, 4, 64))
    );

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

fn register(ins: &ag_engine::cpu_context::DecodedInsn, i: usize) -> RegisterId {
    match ins.operands[i] {
        Operand::Register(r) => r,
        other => panic!("operand {i} is {other:?}, not a register"),
    }
}

#[test]
fn ah_and_rsp_are_different_registers() {
    let mut ctx = X86IcedContext::default();
    let mov_ah = ctx.decode(&[0x88, 0xe0], 0x1000).expect("mov al, ah");
    let ah = register(&mov_ah, 1);
    let mov_rsp = ctx
        .decode(&[0x48, 0x89, 0xe0], 0x1000)
        .expect("mov rax, rsp");
    let rsp = register(&mov_rsp, 1);
    assert_ne!(ah, rsp);
    assert_eq!(
        ah,
        RegisterId::slice(RC_GPR, 0, 8, 8),
        "AH is the high byte of RAX"
    );
    assert_eq!(rsp, RegisterId::new(RC_GPR, 4, 64));
    assert!(
        ah.same_register(&register(&mov_rsp, 0)),
        "AH and RAX are one register"
    );
}

#[test]
fn operand_width_is_part_of_the_identity() {
    let mut ctx = X86IcedContext::default();
    let mov32 = ctx.decode(&[0x89, 0xc0], 0x1000).expect("mov eax, eax");
    let mov64 = ctx
        .decode(&[0x48, 0x89, 0xc0], 0x1000)
        .expect("mov rax, rax");
    assert_ne!(mov32.operands, mov64.operands);
    assert_eq!(register(&mov32, 0).bit_size, 32);
    assert_eq!(register(&mov64, 0).bit_size, 64);
    assert!(register(&mov32, 0).same_register(&register(&mov64, 0)));
}

#[test]
fn vector_registers_are_numbered_and_sized() {
    let mut ctx = X86IcedContext::default();
    // vpxor ymm2, ymm0, ymm1
    let vpxor = ctx
        .decode(&[0xc5, 0xfd, 0xef, 0xd1], 0x1000)
        .expect("vpxor ymm2, ymm0, ymm1");
    let regs: Vec<RegisterId> = (0..3).map(|i| register(&vpxor, i)).collect();
    assert_eq!(regs[0], RegisterId::new(RC_VEC, 2, 256));
    assert_eq!(regs[1], RegisterId::new(RC_VEC, 0, 256));
    assert_eq!(regs[2], RegisterId::new(RC_VEC, 1, 256));
    // pxor xmm2, xmm1 is the same file at 128 bits.
    let pxor = ctx
        .decode(&[0x66, 0x0f, 0xef, 0xd1], 0x1000)
        .expect("pxor xmm2, xmm1");
    assert_eq!(register(&pxor, 0), RegisterId::new(RC_VEC, 2, 128));
    assert!(register(&pxor, 0).same_register(&regs[0]));
}

#[test]
fn segment_registers_keep_their_own_numbers() {
    let mut ctx = X86IcedContext::default();
    let mov_fs = ctx.decode(&[0x8c, 0xe0], 0x1000).expect("mov eax, fs");
    let mov_gs = ctx.decode(&[0x8c, 0xe8], 0x1000).expect("mov eax, gs");
    let fs = register(&mov_fs, 1);
    let gs = register(&mov_gs, 1);
    assert_eq!(fs.class, RC_SEG);
    assert_ne!(fs, gs);
    let mut set = RegisterSet::empty();
    set.insert(fs);
    assert!(set.contains(fs));
    assert!(!set.contains(gs));
}
