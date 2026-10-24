use ag_engine::cpu_context::{
    CpuContext, Flow, Operand, X86IcedContext, RC_GPR, RC_NONE, RC_SEG, RC_VEC,
};
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
fn hlt_is_a_halt_and_decoding_continues_past_it() {
    // hlt ; nop — the C runtime's _start ends in hlt, and padding follows.
    let bytes = [0xf4, 0x90];
    let mut ctx = X86IcedContext::default();
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx, &bytes, 0x1000)
        .expect("a halt must not abort the segment");
    assert_eq!(dys.instructions.len(), 2);
    assert_eq!(dys.instructions[0].flow, Flow::Halt);
    assert_eq!(dys.instructions[0].length, 1);
    assert_eq!(dys.instructions[1].flow, Flow::Next);
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

#[test]
fn undecodable_bytes_are_recorded_one_at_a_time_and_decoding_continues() {
    // ret ; 0x06 (invalid in 64-bit mode) ; ret
    let bytes = [0xc3, 0x06, 0xc3];
    let mut ctx = X86IcedContext::default();
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx, &bytes, 0x1000)
        .expect("an invalid byte must not abort the segment");
    assert_eq!(dys.instructions.len(), 3);
    assert_eq!(dys.instructions[0].flow, Flow::Return);
    assert_eq!(dys.instructions[1].flow, Flow::Invalid);
    assert_eq!(dys.instructions[1].length, 1);
    assert_eq!(dys.instructions[2].address, 0x1002);
    assert_eq!(dys.instructions[2].flow, Flow::Return);
}

// ---- 32-bit code -----------------------------------------------------------
//
// The width of a program comes from its language, and the decoder reads the
// bytes the way that width says: `push ebp; mov ebp, esp` is `55 89 e5` in a
// 32-bit program, where `48` is `dec eax` and not a REX prefix.

use ag_engine::Bitness;

/// `add` of the 32-bit fixture: push ebp; mov ebp,esp; mov edx,[ebp+8];
/// mov eax,[ebp+0xc]; add eax,edx; pop ebp; ret.
const CODE32: &[u8] = &[
    0x55, 0x89, 0xe5, 0x8b, 0x55, 0x08, 0x8b, 0x45, 0x0c, 0x01, 0xd0, 0x5d, 0xc3,
];

#[test]
fn the_decoder_of_a_language_reads_the_width_the_language_names() {
    let ctx = X86IcedContext::of_language("x86:LE:32:default:gcc").expect("32-bit x86");
    assert_eq!(ctx.bitness(), Bitness::Bits32);
    assert_eq!(ctx.byte_size(), 4, "a pointer is four bytes");

    let ctx = X86IcedContext::of_language("x86:LE:64:default:windows").expect("64-bit x86");
    assert_eq!(ctx.bitness(), Bitness::Bits64);
    assert_eq!(ctx.byte_size(), 8);

    assert!(
        X86IcedContext::of_language("ARM:LE:32:v8").is_none(),
        "the decoder reads x86 and nothing else"
    );
    assert!(
        X86IcedContext::of_language("x86:LE").is_none(),
        "a language with no width names no decoder"
    );
    assert_eq!(X86IcedContext::default().bitness(), Bitness::Bits64);
}

#[test]
fn a_32_bit_prologue_decodes_as_32_bit_code() {
    let mut ctx = X86IcedContext::new(Bitness::Bits32);
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx, CODE32, 0x8049000).expect("add");

    let mnemonics: Vec<u32> = dys.instructions.iter().map(|i| i.mnemonic).collect();
    assert_eq!(
        mnemonics,
        vec![
            iced_x86::Mnemonic::Push as u32,
            iced_x86::Mnemonic::Mov as u32,
            iced_x86::Mnemonic::Mov as u32,
            iced_x86::Mnemonic::Mov as u32,
            iced_x86::Mnemonic::Add as u32,
            iced_x86::Mnemonic::Pop as u32,
            iced_x86::Mnemonic::Ret as u32,
        ]
    );
    assert_eq!(dys.instructions[6].flow, Flow::Return);
    assert_eq!(dys.instructions[6].address, 0x804900c);
}

#[test]
fn in_32_bit_code_the_32_bit_registers_are_the_full_registers() {
    let mut ctx = X86IcedContext::new(Bitness::Bits32);
    let mov = ctx.decode(&CODE32[1..], 0x8049001).expect("mov ebp, esp");

    // `ebp` is the whole of GPR 5 and `esp` the whole of GPR 4: a register of
    // 32 bits with no slice taken out of it.
    assert_eq!(register(&mov, 0), RegisterId::new(RC_GPR, 5, 32));
    assert_eq!(register(&mov, 1), RegisterId::new(RC_GPR, 4, 32));
    assert_eq!(register(&mov, 1).bit_offset, 0);

    // The same ids a 64-bit listing gives `ebp` and `esp`, so the two widths
    // name a register the same way.
    let mut ctx64 = X86IcedContext::new(Bitness::Bits64);
    let mov64 = ctx64.decode(&[0x89, 0xe5], 0x1000).expect("mov ebp, esp");
    assert_eq!(mov.operands, mov64.operands);

    // `ah` is still the high byte of GPR 0, and `[ebp+8]` is based on GPR 5.
    let mov_ah = ctx.decode(&[0x88, 0xe0], 0x1000).expect("mov al, ah");
    assert_eq!(register(&mov_ah, 1), RegisterId::slice(RC_GPR, 0, 8, 8));
    let load = ctx
        .decode(&CODE32[3..], 0x8049003)
        .expect("mov edx, [ebp+8]");
    match load.operands[1] {
        Operand::Mem {
            base,
            index,
            disp,
            size,
            ..
        } => {
            assert_eq!(base, RegisterId::new(RC_GPR, 5, 32));
            assert_eq!(index, RegisterId::new(RC_NONE, 0, 0));
            assert_eq!(disp, 8);
            assert_eq!(size, 4);
        }
        other => panic!("not a memory operand: {other:?}"),
    }
}

#[test]
fn a_rex_prefix_is_an_instruction_in_32_bit_code() {
    // 48 89 e5 is `mov rbp, rsp` in 64-bit code and `dec eax; mov ebp, esp`
    // in 32-bit code.
    let mut ctx32 = X86IcedContext::new(Bitness::Bits32);
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx32, &CODE[1..4], 0x1000).unwrap();
    assert_eq!(dys.instructions.len(), 2);
    assert_eq!(dys.instructions[0].mnemonic, iced_x86::Mnemonic::Dec as u32);
    assert_eq!(dys.instructions[0].length, 1);
    assert_eq!(dys.instructions[1].mnemonic, iced_x86::Mnemonic::Mov as u32);

    let mut ctx64 = X86IcedContext::new(Bitness::Bits64);
    let dys = ag_engine::pipeline::Disasm::decode(&mut ctx64, &CODE[1..4], 0x1000).unwrap();
    assert_eq!(dys.instructions.len(), 1);
    assert_eq!(
        register(&dys.instructions[0], 0),
        RegisterId::new(RC_GPR, 5, 64)
    );
}

#[test]
fn a_byte_that_is_data_in_64_bit_code_is_an_instruction_in_32_bit_code() {
    // 0x06 is `push es` in 32-bit code and nothing in 64-bit code.
    let mut ctx32 = X86IcedContext::new(Bitness::Bits32);
    let push_es = ctx32.decode(&[0x06], 0x1000).expect("push es");
    assert_eq!(push_es.flow, Flow::Next);
    assert_eq!(push_es.mnemonic, iced_x86::Mnemonic::Push as u32);
    assert_eq!(register(&push_es, 0).class, RC_SEG);

    let mut ctx64 = X86IcedContext::new(Bitness::Bits64);
    assert_eq!(ctx64.decode(&[0x06], 0x1000).unwrap().flow, Flow::Invalid);
}

#[test]
fn an_absolute_memory_operand_is_the_pointer_of_32_bit_code() {
    let mut ctx = X86IcedContext::new(Bitness::Bits32);

    // mov edx, [0x804b008] — the way `main` of the fixture reads `counter`.
    let load = ctx
        .decode(&[0x8b, 0x15, 0x08, 0xb0, 0x04, 0x08], 0x804903e)
        .expect("mov edx, [0x804b008]");
    assert_eq!(
        load.rip_relative_address, None,
        "there is no rip in 32-bit code"
    );
    assert_eq!(load.absolute_address, Some(0x804b008));
    assert_eq!(load.memory_address(), Some(0x804b008));

    // mov eax, [0x804b00c] in its short form, with no modrm at all.
    let moffs = ctx
        .decode(&[0xa1, 0x0c, 0xb0, 0x04, 0x08], 0x8049049)
        .expect("mov eax, [0x804b00c]");
    assert_eq!(moffs.memory_address(), Some(0x804b00c));

    // A displacement off a register is not an address: [ebp+8] is a local.
    let local = ctx
        .decode(&CODE32[3..], 0x8049003)
        .expect("mov edx, [ebp+8]");
    assert_eq!(local.memory_address(), None);

    // A segment override takes the operand out of the program's address
    // space: gs:[0x14] is the stack guard, not the 20th byte of the program.
    let guard = ctx
        .decode(&[0x65, 0xa1, 0x14, 0x00, 0x00, 0x00], 0x1000)
        .expect("mov eax, gs:[0x14]");
    assert_eq!(guard.memory_address(), None);

    // A register operand names no address.
    let add = ctx.decode(&[0x01, 0xd0], 0x1000).expect("add eax, edx");
    assert_eq!(add.memory_address(), None);
}

#[test]
fn the_pointer_of_64_bit_code_is_still_the_rip_relative_operand() {
    let mut ctx = X86IcedContext::new(Bitness::Bits64);
    let lea = ctx
        .decode(&CODE[4..], 0x1004)
        .expect("lea rax, [rip+0x44332211]");
    assert_eq!(
        lea.absolute_address, None,
        "a rip-relative operand has a base"
    );
    assert_eq!(lea.memory_address(), lea.rip_relative_address);

    // fs:[0x28] is the stack guard of 64-bit code, and names nothing.
    let guard = ctx
        .decode(
            &[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00],
            0x1000,
        )
        .expect("mov rax, fs:[0x28]");
    assert_eq!(guard.memory_address(), None);

    // A 64-bit program that is not position-independent names its data
    // outright too: mov eax, [0x404010].
    let absolute = ctx
        .decode(&[0x8b, 0x04, 0x25, 0x10, 0x40, 0x40, 0x00], 0x1000)
        .expect("mov eax, [0x404010]");
    assert_eq!(absolute.memory_address(), Some(0x404010));
}

#[test]
fn a_branch_in_32_bit_code_lands_where_the_32_bit_target_says() {
    let mut ctx = X86IcedContext::new(Bitness::Bits32);
    // jle -0x1b from 0x804903c: the loop of `main` of the fixture.
    let jle = ctx.decode(&[0x7e, 0xe5], 0x804903c).expect("jle");
    assert_eq!(jle.flow, Flow::ConditionalBranch(0x8049023));
    // call -0x2e from 0x8049029: the call to `add`.
    let call = ctx
        .decode(&[0xe8, 0xd2, 0xff, 0xff, 0xff], 0x8049029)
        .expect("call add");
    assert_eq!(call.flow, Flow::Call(0x8049000));
    // A call to the next instruction lands five bytes on.
    let next = ctx.decode(&[0xe8, 0x00, 0x00, 0x00, 0x00], 0x1000).unwrap();
    assert_eq!(next.flow, Flow::Call(0x1005));
}
