//! Return-value liveness: whether anything reads the value a call leaves in
//! `rax`.
//!
//! The lifter decides a function's return type from use, not presence
//! ([`crate::lift`], the `return-liveness` option). The use it asks about
//! is the callers': after `call f`, does the caller read `eax` or `rax`
//! before it writes it? [`result_use_after`] answers that for one call site
//! by walking the caller's control-flow graph from the instruction after
//! the call, and the image answers for every call site of a function
//! through [`crate::lift::Symbols::result_uses`].
//!
//! The walk is a forward search over the caller's blocks. On each path the
//! first instruction that touches `rax` decides it: a read — a store of
//! `eax`, a `cmp` or `test`, a move into another register, a memory operand
//! addressed through it, `cdqe`, a `call` or `jmp` through it — makes the
//! value *read*, at the width of the slice read; a write with no read first
//! — a load into `eax`, `xor eax, eax`, a `pop rax`, another `call`, which
//! clobbers it — makes it *killed*. A write of only part of the register
//! (`mov al, 1`) counts as a kill too. A `ret` with the value untouched
//! means the caller *returns* it, and whether that is a use is its callers'
//! question, which the lifter asks in turn. A `jmp` out of the function
//! with the value untouched is a tail call to something that does not take
//! `rax`, and a kill. Paths are combined by the strongest answer: any read
//! wins, then any return, then killed.

use std::collections::BTreeSet;

use crate::cfg::ProcedureCfg;
use crate::cpu_context::{DecodedInsn, Flow, RC_GPR};
use crate::pipeline::Disasm;

/// What a caller does with the value a call left in `rax`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultUse {
    /// Read before it is written: `bits` is the widest slice read on any
    /// path (8 for `al`, 32 for `eax`, 64 for `rax`).
    Read { bits: u32 },
    /// Written, or clobbered by another call, before any read on every
    /// path: nothing the callee left is used.
    Killed,
    /// Carried untouched to a `ret` on some path and read on none: the
    /// caller returns it, and whether that is a use is the caller's
    /// callers' question.
    Returned,
}

/// One call site of a function, and what the caller does with the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSiteUse {
    /// The caller's entry address.
    pub caller: u64,
    /// The caller's name, as the image spells it (`sub_<hex>` when it has
    /// none).
    pub caller_name: String,
    /// The address of the `call` — or of the `jmp`, for a tail call.
    pub site: u64,
    /// What the caller does with the result.
    pub result: ResultUse,
}

/// The GPR index of `rax`.
const RAX: u32 = 0;

/// What the caller whose code is `disasm`, walked into `cfg`, does with the
/// value in `rax` after the `call` at `site`.
///
/// The walk starts at the instruction after `site` and follows the graph
/// forward, each block once. A site that is not in the graph — one the
/// walk never reached — is [`ResultUse::Killed`]: nothing is known to read
/// it.
pub fn result_use_after(disasm: &Disasm, cfg: &ProcedureCfg, site: u64) -> ResultUse {
    let Some(block) = cfg.block_containing(site) else {
        return ResultUse::Killed;
    };

    let mut read: Option<u32> = None;
    let mut returned = false;
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    // Each entry is a block to scan, from the instruction after `after`
    // when that is given, else from its first.
    let mut pending: Vec<(u64, Option<u64>)> = vec![(block.from, Some(site))];

    while let Some((from, after)) = pending.pop() {
        if after.is_none() && !seen.insert(from) {
            continue;
        }
        let Some(block) = cfg
            .block_containing(from)
            .filter(|block| block.from == from)
        else {
            continue;
        };
        let instructions = disasm.instructions.iter().filter(|ins| {
            block.contains(ins.address) && after.is_none_or(|after| ins.address > after)
        });

        let mut decided = false;
        for ins in instructions {
            match rax_access(ins) {
                RaxAccess::Read(bits) => {
                    read = Some(read.map_or(bits, |known| known.max(bits)));
                    decided = true;
                    break;
                }
                RaxAccess::Killed => {
                    decided = true;
                    break;
                }
                RaxAccess::Untouched => {}
            }
            match ins.flow {
                Flow::Return => {
                    returned = true;
                    decided = true;
                    break;
                }
                // The callee clobbers rax; so does whatever a jmp out of
                // the function lands in, and nothing is known past a trap
                // or a halt.
                Flow::Call(_)
                | Flow::IndirectCall
                | Flow::IndirectBranch
                | Flow::Trap
                | Flow::Halt
                | Flow::Invalid => {
                    decided = true;
                    break;
                }
                Flow::UnconditionalBranch(target)
                    if cfg
                        .block_containing(target)
                        .is_none_or(|block| block.from != target) =>
                {
                    decided = true;
                    break;
                }
                // The syscall number is rax.
                Flow::Syscall => {
                    read = Some(read.map_or(64, |known| known.max(64)));
                    decided = true;
                    break;
                }
                _ => {}
            }
        }
        if !decided {
            for &successor in &block.successor_addresses {
                pending.push((successor, None));
            }
        }
    }

    match (read, returned) {
        (Some(bits), _) => ResultUse::Read { bits },
        (None, true) => ResultUse::Returned,
        (None, false) => ResultUse::Killed,
    }
}

/// How one instruction touches `rax`.
enum RaxAccess {
    /// Reads a slice of it, of this many bits, before any write.
    Read(u32),
    /// Writes some of it without reading it first.
    Killed,
    /// Leaves it alone, or may leave it alone (a conditional write).
    Untouched,
}

/// How `ins` touches `rax`: a read of any slice is a read, at the slice's
/// width counted from the register's low end; else a write of any slice,
/// conditional writes aside, is a kill.
fn rax_access(ins: &DecodedInsn) -> RaxAccess {
    let uses = ins
        .register_uses
        .iter()
        .filter(|use_| use_.register.class == RC_GPR && use_.register.index == RAX);
    let mut killed = false;
    let mut read: Option<u32> = None;
    for use_ in uses {
        let bits = use_.register.bit_size + use_.register.bit_offset;
        if use_.access.reads() {
            read = Some(read.map_or(bits, |known| known.max(bits)));
        }
        if use_.access.kills() {
            killed = true;
        }
    }
    match (read, killed) {
        (Some(bits), _) => RaxAccess::Read(bits),
        (None, true) => RaxAccess::Killed,
        (None, false) => RaxAccess::Untouched,
    }
}

/// The name of the slice of `rax` that `bits` bits are.
pub fn rax_name(bits: u32) -> &'static str {
    match bits {
        8 => "al",
        16 => "ax",
        32 => "eax",
        _ => "rax",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfgwalk::resolve_branches;
    use crate::cpu_context::X86IcedContext;

    const BASE: u64 = 0x1000;

    /// `call f` at the start of the code, to 0x2000.
    const CALL: [u8; 5] = [0xe8, 0xfb, 0x0f, 0x00, 0x00];

    /// Walk `bytes` as a function at [`BASE`] whose first instruction is the
    /// call at `site`, and say what it does with the result.
    fn use_after(bytes: &[u8]) -> ResultUse {
        let mut ctx = X86IcedContext::default();
        let disasm = Disasm::decode(&mut ctx, bytes, BASE).expect("the code decodes");
        let cfg = resolve_branches(&disasm, BASE);
        result_use_after(&disasm, &cfg, BASE)
    }

    fn code(tail: &[u8]) -> Vec<u8> {
        let mut code = CALL.to_vec();
        code.extend_from_slice(tail);
        code
    }

    #[test]
    fn a_store_a_compare_and_a_move_of_eax_read_it() {
        // call f; mov [rbp-0xc], eax; ret
        assert_eq!(
            use_after(&code(&[0x89, 0x45, 0xf4, 0xc3])),
            ResultUse::Read { bits: 32 }
        );
        // call f; test eax, eax; ret
        assert_eq!(
            use_after(&code(&[0x85, 0xc0, 0xc3])),
            ResultUse::Read { bits: 32 }
        );
        // call f; mov rdi, rax; call g; ret: passed as an argument
        assert_eq!(
            use_after(&code(&[
                0x48, 0x89, 0xc7, 0xe8, 0xf4, 0x1f, 0x00, 0x00, 0xc3
            ])),
            ResultUse::Read { bits: 64 }
        );
        // call f; mov [rbp-8], rax; ret
        assert_eq!(
            use_after(&code(&[0x48, 0x89, 0x45, 0xf8, 0xc3])),
            ResultUse::Read { bits: 64 }
        );
        // call f; cdqe; ret: a sign extension reads eax
        assert_eq!(
            use_after(&code(&[0x48, 0x98, 0xc3])),
            ResultUse::Read { bits: 32 }
        );
    }

    #[test]
    fn a_write_or_another_call_before_any_read_kills_it() {
        // call f; mov eax, 0; ret
        assert_eq!(
            use_after(&code(&[0xb8, 0, 0, 0, 0, 0xc3])),
            ResultUse::Killed
        );
        // call f; xor eax, eax; ret
        assert_eq!(use_after(&code(&[0x31, 0xc0, 0xc3])), ResultUse::Killed);
        // call f; mov rax, [rbp-8]; ret
        assert_eq!(
            use_after(&code(&[0x48, 0x8b, 0x45, 0xf8, 0xc3])),
            ResultUse::Killed
        );
        // call f; call g; ret
        assert_eq!(
            use_after(&code(&[0xe8, 0xf6, 0x1f, 0x00, 0x00, 0xc3])),
            ResultUse::Killed
        );
        // call f; mov al, 1; ret: a partial write is a kill too
        assert_eq!(use_after(&code(&[0xb0, 0x01, 0xc3])), ResultUse::Killed);
        // call f; jmp 0x3000: a tail call out of the function
        assert_eq!(
            use_after(&code(&[0xe9, 0xf6, 0x1f, 0x00, 0x00])),
            ResultUse::Killed
        );
    }

    #[test]
    fn a_ret_with_it_untouched_returns_it() {
        // call f; ret
        assert_eq!(use_after(&code(&[0xc3])), ResultUse::Returned);
        // call f; mov byte ptr [rip+x], 1; pop rbp; ret
        assert_eq!(
            use_after(&code(&[
                0xc6, 0x05, 0x10, 0x00, 0x00, 0x00, 0x01, 0x5d, 0xc3
            ])),
            ResultUse::Returned
        );
        // call f; leave; ret
        assert_eq!(use_after(&code(&[0xc9, 0xc3])), ResultUse::Returned);
    }

    #[test]
    fn the_paths_after_a_branch_are_combined_and_a_read_wins() {
        // call f; cmp edi, 0; je +6; mov eax, 1; ret; mov [rbp-0xc], eax; ret
        let tail = [
            0x83, 0xff, 0x00, // cmp edi, 0
            0x74, 0x06, // je +6
            0xb8, 1, 0, 0, 0,    // mov eax, 1
            0xc3, // ret
            0x89, 0x45, 0xf4, // mov [rbp-0xc], eax
            0xc3, // ret
        ];
        assert_eq!(use_after(&code(&tail)), ResultUse::Read { bits: 32 });

        // call f; cmp edi, 0; je +6; mov eax, 1; ret; ret: killed on one
        // path, returned on the other
        let tail = [0x83, 0xff, 0x00, 0x74, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0xc3];
        assert_eq!(use_after(&code(&tail)), ResultUse::Returned);

        // the widest read of several: mov edi, eax on one path, mov rsi,
        // rax on the other
        let tail = [
            0x83, 0xff, 0x00, // cmp edi, 0
            0x74, 0x03, // je +3
            0x89, 0xc7, // mov edi, eax
            0xc3, // ret
            0x48, 0x89, 0xc6, // mov rsi, rax
            0xc3, // ret
        ];
        assert_eq!(use_after(&code(&tail)), ResultUse::Read { bits: 64 });
    }

    #[test]
    fn a_loop_after_the_call_is_walked_once() {
        // call f; L: cmp edi, 0; jne L; ret
        let tail = [0x83, 0xff, 0x00, 0x75, 0xfb, 0xc3];
        assert_eq!(use_after(&code(&tail)), ResultUse::Returned);
    }

    #[test]
    fn a_site_the_walk_never_reached_is_killed() {
        // ret; call f: the call is after the return and never reached
        let mut ctx = X86IcedContext::default();
        let mut bytes = vec![0xc3];
        bytes.extend_from_slice(&CALL);
        let disasm = Disasm::decode(&mut ctx, &bytes, BASE).expect("decodes");
        let cfg = resolve_branches(&disasm, BASE);
        assert_eq!(result_use_after(&disasm, &cfg, BASE + 1), ResultUse::Killed);
    }

    #[test]
    fn the_slices_of_rax_have_names() {
        assert_eq!(rax_name(8), "al");
        assert_eq!(rax_name(16), "ax");
        assert_eq!(rax_name(32), "eax");
        assert_eq!(rax_name(64), "rax");
    }
}
