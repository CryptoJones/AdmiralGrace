//! Platform types: the default types of each platform, extended by the
//! analyst (#378).
//!
//! A platform is an operating system and an architecture — `windows/x86-64`,
//! `linux/x86-64`, `macos/arm64` — and each carries the types its images name:
//! the Windows SDK's `HANDLE`, `DWORD`, `SIZE_T` and the `SECURITY_ATTRIBUTES`
//! and `OVERLAPPED` structures, the Linux and macOS C libraries' `FILE`,
//! `timeval`, `sockaddr_in` and the rest. The defaults are C in
//! [`crate::typelib`]'s dialect, read under the platform's data model; they
//! stand under the project's types and the libraries an image imports, so
//! the project wins where both define a name, and a name both define the
//! same way is held once.
//!
//! The analyst extends a platform in two places, and the engine merges them
//! in one ([`effective`]) so every view agrees:
//!
//! - **the user types of the platform**: a file of C the analyst keeps
//!   beside their own configuration, per platform, under
//!   `$XDG_CONFIG_HOME/ag/platform/<os>-<arch>.h` or
//!   `~/.config/ag/platform/<platform>.h`;
//! - **the project's types**: the definitions the project records, which
//!   open on the platform the target is, so a project's `struct timeval`
//!   corrects the platform's where the two disagree.
//!
//! [`effective`] reads the platform's defaults, then the user types, then
//! the project's, each on top of the last; a definition a higher layer
//! gives a name the platform already holds with a different shape takes
//! that name's place, so the store never holds two shapes of one name.

use std::path::PathBuf;

use crate::ctype::{TypeText, parse_into};
use crate::types::{DataModel, TypeStore};

/// The default types of every platform, as C under each data model.
pub mod defaults {
    /// linux/x86-64 and linux/aarch64: the LP64 syscalls, the C library,
    /// and the `pthread` and `sigset_t` shapes.
    pub const LINUX: &str = include_str!("platform/linux.h");
    /// windows/x86-64: the Windows SDK aliases and structures, LLP64.
    pub const WINDOWS: &str = include_str!("platform/windows.h");
    /// macos/x86-64 and macos/arm64: the LP64 Mach-O defaults — `FILE` as
    /// an opaque pointer, the Darwin `sockaddr_in`, `dispatch_queue_t`.
    pub const MACOS: &str = include_str!("platform/macos.h");
    /// The remaining platforms a raw image may be: ILP32 and the 32-bit
    /// x86 model, under the same C library definitions.
    pub const ILP32: &str = include_str!("platform/ilp32.h");
}

/// One platform: an operating system and an architecture, and the data
/// model the architecture implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Platform {
    /// The operating system: `windows`, `linux`, `macos`, or a raw image's
    /// word for what it is itself.
    pub os: Os,
    /// The architecture: a raw language's processor word, lower-cased.
    pub arch: &'static str,
}

impl Platform {
    /// The platform's name in a path, a project field and a message:
    /// `windows/x86-64`, `linux/arm64`.
    pub fn name(self) -> String {
        format!("{}/{}", self.os.as_str(), self.arch)
    }

    /// The data model the platform is laid out under: Windows is LLP64
    /// at 64 bits and ILP32 at 32; the rest follow the architecture's
    /// width, as [`DataModel::of_language`] says.
    pub fn data_model(self) -> DataModel {
        let width = arch_bits(self.arch).unwrap_or(64);
        match (self.os, width) {
            (Os::Windows, 64) => DataModel::LLP64,
            (Os::Windows, _) => DataModel {
                wchar: 2,
                ..DataModel::ILP32
            },
            (_, 64) => DataModel::LP64,
            (_, 32) if self.arch == "x86" => DataModel::ILP32_I386,
            (_, _) => DataModel::ILP32,
        }
    }

    /// The platform where `language` names one: a SLEIGH id such as
    /// `x86:LE:64:default:windows` or `AARCH64:LE:64:v8A:default`.
    pub fn of_language(language: &str) -> Option<Platform> {
        let fields: Vec<&str> = language.split(':').collect();
        let processor = fields.first().copied().unwrap_or("").to_ascii_lowercase();
        let windows = fields.get(4).is_some_and(|c| *c == "windows");
        let width = fields.get(2).copied().unwrap_or("");
        let arch = arch_of(&processor, width)?;
        let os = if windows {
            Os::Windows
        } else if language.contains("macos") || language.contains("darwin") || language.contains("mach-o") {
            Os::Macos
        } else {
            Os::Linux
        };
        Some(Platform { os, arch })
    }

    /// The platform a file of this container, decoded as `language`, is:
    /// a PE is Windows, a Mach-O is macOS, an ELF is Linux, and raw bytes
    /// are what their language says.
    pub fn of_image(format: &str, language: &str) -> Option<Platform> {
        let mut platform = Platform::of_language(language)?;
        match format {
            "pe" => platform.os = Os::Windows,
            "macho" => platform.os = Os::Macos,
            "elf" | "raw" => {}
            _ => {}
        }
        Some(platform)
    }

    /// The platform the words `os/arch` name, when they name one: `windows`,
    /// `win32`, `macos`, `darwin`, `linux`, `bsd`, and the architecture
    /// words [`raw_language`](crate::image::raw_language) knows.
    pub fn parse(text: &str) -> Option<Platform> {
        let (os, arch) = text.split_once('/')?;
        let os = Os::parse(os)?;
        let word = match arch.trim().to_ascii_lowercase().as_str() {
            "x86-64" | "x86_64" | "x64" | "amd64" => "x86-64",
            "x86" | "x86-32" | "i386" | "i686" => "x86",
            "arm" | "arm32" | "armv7" => "arm",
            "thumb" | "cortex" => "thumb",
            "aarch64" | "arm64" => "aarch64",
            "riscv64" | "rv64" => "riscv64",
            "riscv32" | "rv32" => "riscv32",
            "msp430" => "msp430",
            "6502" | "m6502" | "mos6502" => "6502",
            "z80" => "z80",
            "superh" | "sh4" | "sh" => "superh",
            _ => return None,
        };
        Some(Platform { os, arch: word })
    }

    /// The platforms the engine ships defaults for, in the order they are
    /// tried: the exact platform, then its OS at any architecture.
    pub fn candidates(self) -> Vec<Platform> {
        let mut out = vec![self];
        for arch in [
            "x86-64", "aarch64", "x86", "arm", "thumb", "riscv64", "riscv32", "msp430", "6502",
            "z80", "superh",
        ] {
            if arch != self.arch {
                out.push(Platform {
                    os: self.os,
                    arch,
                });
            }
        }
        out
    }
}

/// The operating systems a platform may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Os {
    Windows,
    Linux,
    Macos,
    /// A platform the OS is not one of the above: a raw image, firmware,
    /// whose own system is whatever the analyst says it is.
    Other,
}

impl Os {
    /// The OS as it is spelled in a platform name.
    pub fn as_str(self) -> &'static str {
        match self {
            Os::Windows => "windows",
            Os::Linux => "linux",
            Os::Macos => "macos",
            Os::Other => "other",
        }
    }

    /// The OS the words name, when they name one.
    pub fn parse(text: &str) -> Option<Os> {
        Some(match text.trim().to_ascii_lowercase().as_str() {
            "windows" | "win32" | "win64" | "msvc" => Os::Windows,
            "linux" | "gnu" | "glibc" | "bsd" => Os::Linux,
            "macos" | "mac" | "darwin" | "osx" => Os::Macos,
            "other" | "raw" => Os::Other,
            _ => return None,
        })
    }
}

/// The architecture a processor word names, as a platform spells it.
fn arch_of(processor: &str, width: &str) -> Option<&'static str> {
    Some(match processor {
        "x86" => match width {
            "64" => "x86-64",
            _ => "x86",
        },
        "arm" => "arm",
        "aarch64" => "aarch64",
        "mips" => "mips",
        "riscv" => match width {
            "64" => "riscv64",
            _ => "riscv32",
        },
        "ti_msp430" => "msp430",
        "6502" => "6502",
        "z80" => "z80",
        "superh4" => "superh",
        _ => return None,
    })
}

/// The width the architecture word names, in bits, when it names one.
fn arch_bits(arch: &str) -> Option<u64> {
    match arch {
        "x86-64" | "aarch64" | "riscv64" => Some(64),
        "x86" | "arm" | "thumb" | "mips" | "riscv32" | "superh" => Some(32),
        "msp430" | "6502" | "z80" => Some(16),
        _ => None,
    }
}

/// The defaults of `platform`, as C text: the platform's own, or none.
pub fn default_source(platform: Platform) -> Option<&'static str> {
    match platform.os {
        Os::Windows => Some(defaults::WINDOWS),
        Os::Linux => Some(match arch_bits(platform.arch) {
            Some(64) => defaults::LINUX,
            _ => defaults::ILP32,
        }),
        Os::Macos => Some(defaults::MACOS),
        Os::Other => None,
    }
}

/// The definitions `source` holds, split as the typelib's declarations
/// are: each type declaration one [`TypeText`], in order.
fn definitions_of(source: &str) -> Vec<TypeText> {
    crate::propagate::declarations(source)
        .into_iter()
        .filter_map(|declaration| {
            let head = declaration.split_whitespace().next().unwrap_or("");
            if !matches!(head, "struct" | "union" | "enum" | "typedef") {
                return None;
            }
            let name = crate::propagate::definition_name(&declaration);
            (!name.is_empty()).then(|| TypeText {
                name,
                c: format!("{declaration};"),
            })
        })
        .collect()
}

/// The default definitions of `platform`, as C, in order.
pub fn defaults(platform: Platform) -> Vec<TypeText> {
    default_source(platform).map(definitions_of).unwrap_or_default()
}

/// The default definitions of `platform` read into `store`, in order, as
/// far as they read; the ones that do not read are skipped, as the
/// typelib's are.
pub fn apply_defaults(store: &mut TypeStore, platform: Platform) -> Vec<String> {
    let mut notes = Vec::new();
    for definition in defaults(platform) {
        if let Err(error) = parse_into(store, &definition.c) {
            notes.push(format!("{}: {error}", definition.name));
        }
    }
    notes
}

/// The platform's default types on their own: the defaults as a store
/// under the platform's data model, without the user types or the
/// project's.
pub fn default_store(platform: Platform) -> TypeStore {
    let mut store = TypeStore::new(platform.data_model());
    apply_defaults(&mut store, platform);
    store
}

/// The user-editable types of `platform`: the C the analyst keeps for the
/// platform, in its file, when there is one to read. The file is
/// `$XDG_CONFIG_HOME/ag/platform/<os>-<arch>.h`, or `~/.config/ag/platform`.
pub fn user_source(platform: Platform) -> Option<String> {
    user_path(platform).and_then(|path| std::fs::read_to_string(path).ok())
}

/// The file the platform's user types live in, under
/// `$XDG_CONFIG_HOME/ag/platform/<os>-<arch>.h` or `~/.config/ag/platform`.
pub fn user_path(platform: Platform) -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))?,
    };
    Some(
        base.join("ag")
            .join("platform")
            .join(format!("{}.h", platform.name().replace('/', "-"))),
    )
}

/// The user types of one candidate platform, named for the file they are
/// read from.
pub fn user_definitions(platform: Platform) -> Vec<TypeText> {
    user_source(platform)
        .map(|source| definitions_of(&source))
        .unwrap_or_default()
}

/// Every definition `layers` gives, in the order they are read, with the
/// last definition of every name the one that stands: a name a higher
/// layer redefines with another shape is read once, in the higher
/// layer's shape, where the higher layer puts it. A type a layer names
/// and does not define is read where the layer that defines it puts it.
pub fn merged(layers: &[&[TypeText]]) -> Vec<TypeText> {
    use std::collections::BTreeMap;
    let mut held: Vec<TypeText> = Vec::new();
    let mut at: BTreeMap<String, usize> = BTreeMap::new();
    for layer in layers {
        for definition in *layer {
            if let Some(found) = at.remove(&definition.name) {
                held.remove(found);
                for (index, held_def) in held.iter().enumerate().skip(found) {
                    at.insert(held_def.name.clone(), index);
                }
            }
            at.insert(definition.name.clone(), held.len());
            held.push(definition.clone());
        }
    }
    held
}

/// The types of `platform` as the image reads them: the platform's
/// defaults under its data model, then the user types of every candidate
/// platform, then the project's definitions — [the merged ones](merged),
/// so a higher layer's definition of a name stands in its place. A
/// definition that does not read is refused with its name, as the
/// project's are. The notes are the parser's.
pub fn effective(
    platform: Platform,
    project: &[TypeText],
) -> Result<(TypeStore, Vec<String>), String> {
    let model = platform.data_model();
    let mut user: Vec<TypeText> = Vec::new();
    for candidate in platform.candidates() {
        user.extend(user_definitions(candidate));
    }
    let all = merged(&[&defaults(platform), &user, project]);
    crate::ctype::build(model, &all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_language_names_its_platform() {
        assert_eq!(
            Platform::of_language("x86:LE:64:default:windows"),
            Some(Platform {
                os: Os::Windows,
                arch: "x86-64"
            })
        );
        assert_eq!(
            Platform::of_language("AARCH64:LE:64:v8A:default"),
            Some(Platform {
                os: Os::Linux,
                arch: "aarch64"
            })
        );
        assert_eq!(
            Platform::of_language("x86:LE:32:default:gcc"),
            Some(Platform {
                os: Os::Linux,
                arch: "x86"
            })
        );
        assert_eq!(Platform::of_language("PPC:BE:64:default:gcc"), None);
    }

    #[test]
    fn a_container_can_name_another_os() {
        assert_eq!(
            Platform::of_image("pe", "x86:LE:64:default:gcc").map(|p| p.os),
            Some(Os::Windows)
        );
        assert_eq!(
            Platform::of_image("macho", "AARCH64:LE:64:v8A:default").map(|p| p.os),
            Some(Os::Macos)
        );
    }

    #[test]
    fn the_data_model_follows_the_platform() {
        assert_eq!(
            Platform {
                os: Os::Windows,
                arch: "x86-64"
            }
            .data_model()
            .name,
            "LLP64"
        );
        assert_eq!(
            Platform {
                os: Os::Linux,
                arch: "aarch64"
            }
            .data_model()
            .name,
            "LP64"
        );
        assert_eq!(
            Platform {
                os: Os::Linux,
                arch: "x86"
            }
            .data_model()
            .name,
            "ILP32 (i386)"
        );
    }

    #[test]
    fn the_windows_defaults_read_under_llp64() {
        let platform = Platform {
            os: Os::Windows,
            arch: "x86-64",
        };
        let (store, notes) = effective(platform, &[]).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        for name in ["HANDLE", "DWORD", "SIZE_T", "BOOL", "LPCSTR"] {
            assert!(store.key_of(name).is_some(), "no {name}");
        }
        assert!(store.get("struct SECURITY_ATTRIBUTES").is_some());
        // LLP64: HANDLE is a pointer, DWORD and SIZE_T are 4 and 8.
        let handle = store
            .size_of(&crate::types::Type::Named("HANDLE".to_string()))
            .unwrap();
        assert_eq!(handle, 8);
        let dword = store
            .size_of(&crate::types::Type::Named("DWORD".to_string()))
            .unwrap();
        assert_eq!(dword, 4);
    }

    #[test]
    fn the_linux_defaults_read_under_lp64() {
        let platform = Platform {
            os: Os::Linux,
            arch: "x86-64",
        };
        let (store, notes) = effective(platform, &[]).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert!(store.key_of("FILE").is_some());
        assert!(store.get("struct sockaddr_in").is_some());
        assert!(store.key_of("pthread_t").is_some());
        assert!(store.get("struct sigaction").is_some());
    }

    #[test]
    fn the_macos_defaults_read_under_lp64() {
        let platform = Platform {
            os: Os::Macos,
            arch: "aarch64",
        };
        let (store, notes) = effective(platform, &[]).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert!(store.key_of("FILE").is_some());
        assert!(store.key_of("dispatch_queue_t").is_some());
        assert!(store.get("struct sockaddr_in").is_some());
    }

    #[test]
    fn a_project_definition_wins_over_the_platform() {
        let platform = Platform {
            os: Os::Linux,
            arch: "x86-64",
        };
        let project = vec![TypeText {
            name: "pthread_t".to_string(),
            c: "typedef unsigned long long pthread_t;".to_string(),
        }];
        let (store, _) = effective(platform, &project).unwrap();
        let size = store
            .size_of(&crate::types::Type::Named("pthread_t".to_string()))
            .unwrap();
        assert_eq!(size, 8);
    }


    #[test]
    fn mips_reads_ilp32_not_lp64() {
        let platform = Platform::of_language("MIPS:BE:32:default").unwrap();
        assert_eq!(platform.data_model().name, "ILP32");
        assert_eq!(Platform::of_language("x86:LE:16:Real Mode:default").unwrap().arch, "x86");
    }

    #[test]
    fn merged_puts_a_redefinition_where_the_higher_layer_puts_it() {
        let low = vec![
            TypeText { name: "x".to_string(), c: "typedef int x;".to_string() },
            TypeText { name: "y".to_string(), c: "typedef int y;".to_string() },
        ];
        let high = vec![TypeText { name: "x".to_string(), c: "typedef long x;".to_string() }];
        let all = merged(&[&low, &high]);
        assert_eq!(all.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["y", "x"]);
        assert_eq!(all[1].c, "typedef long x;");
    }

    #[test]
    fn the_user_path_has_no_subdirectory() {
        unsafe { std::env::set_var("XDG_CONFIG_HOME", "/tmp"); }
        let path = user_path(Platform { os: Os::Linux, arch: "x86-64" }).unwrap();
        assert_eq!(path, std::path::PathBuf::from("/tmp/ag/platform/linux-x86-64.h"));
        unsafe { std::env::remove_var("XDG_CONFIG_HOME"); }
    }

    #[test]
    fn platform_names_round_trip() {
        for text in ["windows/x86-64", "linux/aarch64", "macos/aarch64"] {
            let platform = Platform::parse(text).unwrap();
            assert_eq!(platform.name(), text);
        }
        assert_eq!(Platform::parse("windows"), None);
        assert_eq!(Platform::parse("windows/x86-64/extra"), None);
    }
}
