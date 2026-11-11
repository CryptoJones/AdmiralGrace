//! The analyst's words on a function's signature and its analysis
//! properties: its prototype, its calling convention, the stack it adjusts
//! on return, the registers it clobbers, and where its arguments and its
//! result live.
//!
//! A wrong signature misleads every caller's pseudocode, so the analyst can
//! say what the bytes do not: that a function takes three arguments though
//! it reads two registers, that it is `__stdcall` and cleans its own stack,
//! that it clobbers `rbx` though the convention says it may not, that its
//! result leaves in `rdx` rather than `rax`. Each part is optional — what is
//! not said, the lift decides as it always did — and a name that is no
//! register, or a convention that is none, is simply not followed.

use crate::lift::{gpr_name, Abi};

/// The analyst's words on one function's signature and how a call to it
/// behaves, read through [`crate::lift::Symbols::function_properties`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionProperties {
    /// The function's C prototype — `int f(int n, char *s)` — whose return
    /// type, parameter types and names the lift reads over its own.
    pub prototype: Option<String>,
    /// The calling convention, by name: `cdecl`, `stdcall`, `win64`, `sysv`,
    /// `go`, `pascal`, and their kind; see [`parse_convention`].
    pub convention: Option<String>,
    /// The bytes the callee takes off the stack on return — the `N` of a
    /// `ret N` — over what the instruction itself says.
    pub stack_adjustment: Option<i64>,
    /// The registers the function clobbers beyond its convention's
    /// caller-saved ones, by name: `rbx`, `r12`.
    pub clobbers: Vec<String>,
    /// The registers the arguments arrive in, in order, by name, over the
    /// convention's own: `rcx`, `rdx`, `r8`.
    pub arguments: Vec<String>,
    /// The register the result leaves in, by name, over `rax`: `rdx`.
    pub returns: Option<String>,
}

impl FunctionProperties {
    /// Whether nothing is said: no prototype, no convention, no adjustment,
    /// no clobbers and no value locations.
    pub fn is_empty(&self) -> bool {
        self.prototype.is_none()
            && self.convention.is_none()
            && self.stack_adjustment.is_none()
            && self.clobbers.is_empty()
            && self.arguments.is_empty()
            && self.returns.is_none()
    }

    /// The argument registers, as GPR indices, in order: the analyst's own
    /// when any name reads, else the convention's, else the program's.
    pub fn argument_registers(&self, abi: Abi) -> Vec<u32> {
        if !self.arguments.is_empty() {
            let named: Vec<u32> = self
                .arguments
                .iter()
                .filter_map(|name| gpr_index(name))
                .collect();
            if !named.is_empty() {
                return named;
            }
        }
        self.convention_abi()
            .unwrap_or(abi)
            .argument_registers()
            .to_vec()
    }

    /// The integer ABI the convention names, when it names one.
    pub fn convention_abi(&self) -> Option<Abi> {
        convention_abi(self.convention.as_deref()?)
    }

    /// The extra registers the function clobbers, as GPR indices; a name
    /// that is no general register is left out.
    pub fn clobber_registers(&self) -> Vec<u32> {
        self.clobbers
            .iter()
            .filter_map(|name| gpr_index(name))
            .collect()
    }

    /// The register the result leaves in, as a GPR index, when one is named
    /// and reads.
    pub fn return_register(&self) -> Option<u32> {
        gpr_index(self.returns.as_deref()?)
    }
}

/// The canonical spelling of a calling convention `word`, when it is one:
/// `__cdecl` and `cdecl` are `cdecl`, `system v` and `amd64` are `sysv`,
/// `golang` is `go`, `delphi` is `pascal`. `None` for a word that names no
/// convention.
pub fn parse_convention(word: &str) -> Option<&'static str> {
    let word = word.trim().to_ascii_lowercase();
    let word = word.as_str();
    match word {
        "__cdecl" | "cdecl" => Some("cdecl"),
        "__stdcall" | "stdcall" => Some("stdcall"),
        "__fastcall" | "fastcall" => Some("fastcall"),
        "__thiscall" | "thiscall" => Some("thiscall"),
        "__vectorcall" | "vectorcall" => Some("vectorcall"),
        "__clrcall" | "clrcall" => Some("clrcall"),
        "sysv" | "systemv" | "system v" | "amd64" | "unix" | "linux" => Some("sysv"),
        "win64" | "windows" | "ms" | "microsoft" | "msx64" => Some("win64"),
        "go" | "golang" | "go-register" => Some("go"),
        "pascal" | "__pascal" | "delphi" | "borland" => Some("pascal"),
        _ => None,
    }
}

/// The integer ABI a convention `word` implies: `cdecl` and `sysv` pass
/// arguments as System V does, the Microsoft conventions as Win64 does,
/// `go` as Go's register ABI does and `pascal` as the Borland register
/// convention does. `None` for a word that names no convention.
pub fn convention_abi(word: &str) -> Option<Abi> {
    match parse_convention(word)? {
        "cdecl" | "sysv" => Some(Abi::SystemV),
        "go" => Some(Abi::Go),
        "pascal" => Some(Abi::Pascal),
        _ => Some(Abi::Win64),
    }
}

/// The GPR index a register `name` names, at any width: `rdi`, `edi`, `di`
/// and `dil` are all 7, `r9` and `r9d` are 9. `None` for a name that is no
/// general register.
pub fn gpr_index(name: &str) -> Option<u32> {
    let name = name.trim().to_ascii_lowercase();
    (0..16).find(|&index| {
        [64, 32, 16, 8]
            .iter()
            .any(|&bits| gpr_name(index, bits) == name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_register_name_reads_at_any_width() {
        assert_eq!(gpr_index("rdi"), Some(7));
        assert_eq!(gpr_index("edi"), Some(7));
        assert_eq!(gpr_index("di"), Some(7));
        assert_eq!(gpr_index("dil"), Some(7));
        assert_eq!(gpr_index("RAX"), Some(0));
        assert_eq!(gpr_index("r9d"), Some(9));
        assert_eq!(gpr_index("r15"), Some(15));
        assert_eq!(gpr_index("xmm0"), None);
        assert_eq!(gpr_index(""), None);
    }

    #[test]
    fn nothing_said_is_the_programs_convention() {
        let props = FunctionProperties::default();
        assert!(props.is_empty());
        assert_eq!(
            props.argument_registers(Abi::SystemV),
            Abi::SystemV.argument_registers()
        );
        assert_eq!(props.return_register(), None);
        assert!(props.clobber_registers().is_empty());
    }

    #[test]
    fn the_convention_chooses_the_argument_registers() {
        let props = FunctionProperties {
            convention: Some("win64".to_string()),
            ..Default::default()
        };
        assert_eq!(
            props.argument_registers(Abi::SystemV),
            Abi::Win64.argument_registers()
        );
        let props = FunctionProperties {
            convention: Some("__stdcall".to_string()),
            ..Default::default()
        };
        assert_eq!(props.convention_abi(), Some(Abi::Win64));
        let props = FunctionProperties {
            convention: Some("cdecl".to_string()),
            ..Default::default()
        };
        assert_eq!(props.convention_abi(), Some(Abi::SystemV));
        let props = FunctionProperties {
            convention: Some("golang".to_string()),
            ..Default::default()
        };
        assert_eq!(
            props.argument_registers(Abi::SystemV),
            Abi::Go.argument_registers()
        );
        let props = FunctionProperties {
            convention: Some("delphi".to_string()),
            ..Default::default()
        };
        assert_eq!(
            props.argument_registers(Abi::Win64),
            Abi::Pascal.argument_registers()
        );
    }

    #[test]
    fn the_analysts_registers_win_over_the_convention() {
        let props = FunctionProperties {
            convention: Some("win64".to_string()),
            arguments: vec!["rdi".to_string(), "rsi".to_string()],
            ..Default::default()
        };
        assert_eq!(props.argument_registers(Abi::Win64), vec![7, 6]);
    }

    #[test]
    fn an_unknown_register_is_not_followed() {
        let props = FunctionProperties {
            arguments: vec!["xmm0".to_string()],
            clobbers: vec!["rbx".to_string(), "nope".to_string()],
            returns: Some("rdx".to_string()),
            ..Default::default()
        };
        // No argument name reads, so the convention's own are kept.
        assert_eq!(
            props.argument_registers(Abi::SystemV),
            Abi::SystemV.argument_registers()
        );
        assert_eq!(props.clobber_registers(), vec![3]);
        assert_eq!(props.return_register(), Some(2));
    }

    #[test]
    fn conventions_spell_canonically() {
        assert_eq!(parse_convention("__cdecl"), Some("cdecl"));
        assert_eq!(parse_convention("System V"), Some("sysv"));
        assert_eq!(parse_convention("WINDOWS"), Some("win64"));
        assert_eq!(parse_convention("golang"), Some("go"));
        assert_eq!(parse_convention("Go-Register"), Some("go"));
        assert_eq!(parse_convention("delphi"), Some("pascal"));
        assert_eq!(parse_convention("__Pascal"), Some("pascal"));
        assert_eq!(parse_convention("nope"), None);
        assert_eq!(convention_abi("fastcall"), Some(Abi::Win64));
        assert_eq!(convention_abi("go"), Some(Abi::Go));
        assert_eq!(convention_abi("pascal"), Some(Abi::Pascal));
        assert_eq!(convention_abi("nope"), None);
    }

    #[test]
    fn the_go_and_pascal_registers_are_their_own() {
        // Go's register ABI leads with rax and rbx, and runs to r11.
        assert_eq!(Abi::Go.argument_registers(), &[0, 3, 1, 7, 6, 8, 9, 10, 11]);
        // Pascal leads with rax, rdx, rcx, left to right.
        assert_eq!(Abi::Pascal.argument_registers(), &[0, 2, 1]);
        // Go keeps only the stack and frame pointers and the goroutine
        // pointer r14; Pascal keeps what its 32-bit original keeps.
        assert!(Abi::Go.is_callee_saved(4));
        assert!(Abi::Go.is_callee_saved(5));
        assert!(Abi::Go.is_callee_saved(14));
        assert!(!Abi::Go.is_callee_saved(3));
        assert!(!Abi::Go.is_callee_saved(12));
        assert!(Abi::Pascal.is_callee_saved(3));
        assert!(Abi::Pascal.is_callee_saved(6));
        assert!(Abi::Pascal.is_callee_saved(7));
        assert!(!Abi::Pascal.is_callee_saved(0));
    }
}
