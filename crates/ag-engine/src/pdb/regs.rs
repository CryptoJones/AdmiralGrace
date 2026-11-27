//! CodeView register numbers read back to the names the listing spells (#400).
//!
//! A PDB names a register by its CodeView number (`CV_HREG_e` of
//! Microsoft's `cvconst.h`), and the numbers differ by machine: an x64
//! PDB spells `rcx` 330 where an x86 one spells `ecx` 18. The names
//! here are the engine's own — Intel lower case, `rax`, `ebp` — so a
//! local the PDB keeps in a register is named the way the listing
//! names that register.

/// The machine types whose registers this table reads: Intel 386 and
/// x64. Every other machine's locals are held back rather than guessed.
pub const MACHINE_X86: u16 = 0x14c;
pub const MACHINE_X64: u16 = 0x8664;

/// The register `number` names on `machine`, when it is one the
/// listing spells; `None` for a machine or number not read.
pub fn name(machine: u16, number: u16) -> Option<&'static str> {
    match machine {
        MACHINE_X86 => x86(number),
        MACHINE_X64 => x64(number),
        _ => None,
    }
}

/// Whether `number` is the frame pointer the standard prologue sets
/// up — `ebp` on x86, `rbp` on x64 — whose frame a local's offset is
/// counted from.
pub fn is_frame_pointer(machine: u16, number: u16) -> bool {
    match machine {
        MACHINE_X86 => number == 22,  // CV_REG_EBP
        MACHINE_X64 => number == 334, // CV_AMD64_RBP
        _ => false,
    }
}

/// Whether `number` is the stack pointer (`esp` on x86, `rsp` on x64).
pub fn is_stack_pointer(machine: u16, number: u16) -> bool {
    match machine {
        MACHINE_X86 => number == 21,  // CV_REG_ESP
        MACHINE_X64 => number == 335, // CV_AMD64_RSP
        _ => false,
    }
}

/// The bytes the standard prologue pushes below the entry stack
/// pointer before it sets the frame pointer: the return address's
/// slot, 4 on x86 and 8 on x64. A local at `[bp - n]` is at
/// `entry_sp - n - this`, which is how the lift's `local_<hex>` names
/// count it.
pub fn frame_bias(machine: u16) -> Option<i64> {
    match machine {
        MACHINE_X86 => Some(4),
        MACHINE_X64 => Some(8),
        _ => None,
    }
}

fn x86(n: u16) -> Option<&'static str> {
    Some(match n {
        1 => "al",
        2 => "cl",
        3 => "dl",
        4 => "bl",
        5 => "ah",
        6 => "ch",
        7 => "dh",
        8 => "bh",
        9 => "ax",
        10 => "cx",
        11 => "dx",
        12 => "bx",
        13 => "sp",
        14 => "bp",
        15 => "si",
        16 => "di",
        17 => "eax",
        18 => "ecx",
        19 => "edx",
        20 => "ebx",
        21 => "esp",
        22 => "ebp",
        23 => "esi",
        24 => "edi",
        25 => "es",
        26 => "cs",
        27 => "ss",
        28 => "ds",
        29 => "fs",
        30 => "gs",
        31 => "ip",
        32 => "flags",
        33 => "eip",
        34 => "eflags",
        128..=135 => return st(n - 128),
        154..=161 => return xmm(n - 154),
        _ => return None,
    })
}

fn x64(n: u16) -> Option<&'static str> {
    // The 8/16/32-bit forms keep the x86 numbers; the 64-bit forms
    // and the extended registers have their own.
    if n <= 34 {
        return x86(n);
    }
    Some(match n {
        128..=135 => return st(n - 128),
        154..=161 => return xmm(n - 154),
        252..=259 => return xmm(n - 252 + 8),
        324 => "sil",
        325 => "dil",
        326 => "bpl",
        327 => "spl",
        328 => "rax",
        329 => "rbx",
        330 => "rcx",
        331 => "rdx",
        332 => "rsi",
        333 => "rdi",
        334 => "rbp",
        335 => "rsp",
        336..=343 => return r(n - 336, ""),
        344..=351 => return r(n - 344, "b"),
        352..=359 => return r(n - 352, "w"),
        360..=367 => return r(n - 360, "d"),
        368..=383 => return ymm(n - 368),
        _ => return None,
    })
}

fn st(n: u16) -> Option<&'static str> {
    ["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"]
        .get(n as usize)
        .copied()
}

fn xmm(n: u16) -> Option<&'static str> {
    [
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
        "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    ]
    .get(n as usize)
    .copied()
}

fn ymm(n: u16) -> Option<&'static str> {
    [
        "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10",
        "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
    ]
    .get(n as usize)
    .copied()
}

fn r(n: u16, suffix: &str) -> Option<&'static str> {
    const NAMES: [&str; 8] = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
    const BYTES: [&str; 8] = ["r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"];
    const WORDS: [&str; 8] = ["r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"];
    const DWORDS: [&str; 8] = ["r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"];
    let table = match suffix {
        "" => &NAMES,
        "b" => &BYTES,
        "w" => &WORDS,
        "d" => &DWORDS,
        _ => return None,
    };
    table.get(n as usize).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_x86_and_x64_codeview_registers() {
        assert_eq!(name(MACHINE_X64, 18), Some("ecx"));
        assert_eq!(name(MACHINE_X64, 330), Some("rcx"));
        assert_eq!(name(MACHINE_X64, 328), Some("rax"));
        assert_eq!(name(MACHINE_X64, 332), Some("rsi"));
        assert_eq!(name(MACHINE_X64, 334), Some("rbp"));
        assert_eq!(name(MACHINE_X64, 335), Some("rsp"));
        assert_eq!(name(MACHINE_X64, 343), Some("r15"));
        assert_eq!(name(MACHINE_X64, 360), Some("r8d"));
        assert_eq!(name(MACHINE_X64, 259), Some("xmm15"));
        assert_eq!(name(MACHINE_X86, 22), Some("ebp"));
        assert_eq!(name(MACHINE_X86, 21), Some("esp"));
        assert_eq!(name(MACHINE_X86, 154), Some("xmm0"));
        assert_eq!(name(MACHINE_X86, 330), None);
        assert_eq!(name(0xaa64, 330), None);
        assert!(is_frame_pointer(MACHINE_X86, 22));
        assert!(is_frame_pointer(MACHINE_X64, 334));
        assert!(is_stack_pointer(MACHINE_X86, 21));
        assert!(is_stack_pointer(MACHINE_X64, 335));
        assert_eq!(frame_bias(MACHINE_X86), Some(4));
        assert_eq!(frame_bias(MACHINE_X64), Some(8));
        assert_eq!(frame_bias(0xaa64), None);
    }
}
