//! A loaded program image: the bytes, sections, entry point and symbols of an
//! ELF, PE, COFF or Mach-O file.
//!
//! The parsing is done by [`kuna_analysis`], the loader and analyzer tier of
//! the kuna decompiler, adopted as a pinned git dependency (see
//! `docs/KUNA_CRATES_EVALUATION.md`). This module is the engine's view of it:
//! enough to pick a code section, hand its bytes to the decoder, and name what
//! the walk finds.

use std::path::Path;

use anyhow::{Context, Result};
use kuna_analysis::loadimage_object::ObjectLoadImage;

/// One named section of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The section's name, as the container spells it (`.text`, `__TEXT,__text`).
    pub name: String,
    /// The virtual address the section maps to.
    pub vma: u64,
    /// The section's size in memory.
    pub size: u64,
    /// Whether the section holds code.
    pub executable: bool,
    /// Where the section's bytes start in the file, when the file holds any.
    pub file_offset: Option<u64>,
    /// How many of the section's bytes the file holds.
    pub file_size: Option<u64>,
}

/// A program image read from disk or from bytes.
pub struct Image {
    inner: Loaded,
    bytes: Vec<u8>,
    name: String,
}

/// What the image was read as: a container the loader parsed, or raw bytes
/// the analyst said where to load.
enum Loaded {
    /// Boxed: the loader's reading is large, the raw spec small.
    Object(Box<ObjectLoadImage>),
    Raw(RawSpec),
}

/// How raw bytes — firmware, shellcode, a dump — are to be read: a file with
/// no container to say where it loads, so the analyst says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSpec {
    /// The SLEIGH language id the bytes decode under (see [`raw_language`]).
    pub language: String,
    /// The address the bytes load at.
    pub base: u64,
    /// The entry point, when there is one to name.
    pub entry: Option<u64>,
    /// Where in the file the bytes start.
    pub offset: u64,
    /// How many bytes, or the rest of the file.
    pub length: Option<u64>,
}

/// The language id an architecture's name stands for, as the command line
/// and the workbench spell it: `x86-64`, `x86`, `arm`, `thumb`, `aarch64`.
pub fn raw_language(arch: &str) -> Option<&'static str> {
    Some(match arch.trim().to_ascii_lowercase().as_str() {
        "x86-64" | "x86_64" | "x64" | "amd64" => "x86:LE:64:default:gcc",
        "x86" | "x86-32" | "i386" | "i686" => "x86:LE:32:default:gcc",
        "arm" | "arm32" | "armv7" => "ARM:LE:32:v8:default",
        "thumb" | "cortex" | "cortex-m" => "ARM:LE:32:Cortex:default",
        "aarch64" | "arm64" => "AARCH64:LE:64:v8A:default",
        _ => return None,
    })
}

/// The architecture names [`raw_language`] knows, for a message.
pub const RAW_ARCHITECTURES: &str = "x86-64, x86, arm, thumb, aarch64";

impl std::fmt::Debug for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Image")
            .field("name", &self.name)
            .field("language", &self.language())
            .field("entry", &self.entry())
            .field("sections", &self.sections().len())
            .finish()
    }
}

impl Image {
    /// Read and parse the file at `path`.
    pub fn open(path: &Path) -> Result<Image> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        Image::from_bytes(&name, bytes)
    }

    /// Parse an image already in memory; `name` labels it in errors.
    pub fn from_bytes(name: &str, bytes: Vec<u8>) -> Result<Image> {
        let inner = ObjectLoadImage::from_bytes(name, &bytes)
            .map_err(|error| anyhow::anyhow!("loading {name}: {error}"))?;
        Ok(Image {
            inner: Loaded::Object(Box::new(inner)),
            bytes,
            name: name.to_string(),
        })
    }

    /// Read the file at `path` as raw bytes, loaded as `spec` says: one
    /// section of code at the base, with no symbols but the entry.
    pub fn open_raw(path: &Path, spec: &RawSpec) -> Result<Image> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let file_length = bytes.len() as u64;
        anyhow::ensure!(
            spec.offset < file_length || (spec.offset == 0 && file_length == 0),
            "the offset {:#x} is past the end of {} ({file_length} bytes)",
            spec.offset,
            path.display()
        );
        let rest = file_length - spec.offset;
        let length = match spec.length {
            Some(length) => {
                anyhow::ensure!(
                    length <= rest,
                    "{length} bytes from the offset {:#x} run past the end of {} ({file_length} bytes)",
                    spec.offset,
                    path.display()
                );
                length
            }
            None => rest,
        };
        anyhow::ensure!(
            spec.base.checked_add(length).is_some(),
            "{length} bytes at {:#x} run past the top of the address space",
            spec.base
        );
        if let Some(entry) = spec.entry {
            anyhow::ensure!(
                (entry & !1) >= spec.base && (entry & !1) < spec.base.saturating_add(length),
                "the entry {entry:#x} is outside the bytes, {:#x} to {:#x}",
                spec.base,
                spec.base.saturating_add(length)
            );
        }
        Ok(Image {
            inner: Loaded::Raw(RawSpec {
                length: Some(length),
                ..spec.clone()
            }),
            bytes,
            name: name.to_string(),
        })
    }

    /// The loader's reading of the container, when there is one.
    fn object(&self) -> Option<&ObjectLoadImage> {
        match &self.inner {
            Loaded::Object(inner) => Some(inner.as_ref()),
            Loaded::Raw(_) => None,
        }
    }

    /// How the bytes were said to load, when they are raw bytes.
    pub fn raw(&self) -> Option<&RawSpec> {
        match &self.inner {
            Loaded::Raw(spec) => Some(spec),
            Loaded::Object(_) => None,
        }
    }

    /// The name the image was opened under.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The bytes of the file, as read.
    pub fn file_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// What the image says about which instruction set its 32-bit ARM code
    /// is in, as `(address, thumb)`: the entry point's low bit, which the
    /// loader clears; the assembler's `$t` and `$a` mapping symbols, which
    /// mark where the mode changes; and every function symbol with its low
    /// bit set, which is a Thumb function. Empty for every other
    /// architecture.
    pub fn arm_mode_hints(&self) -> Vec<(u64, bool)> {
        if let Loaded::Raw(spec) = &self.inner {
            // Raw bytes have no symbols; the entry's low bit is all there is.
            return match spec.entry {
                Some(entry) if spec.language.starts_with("ARM:") => {
                    vec![(entry & !1, entry & 1 == 1)]
                }
                _ => Vec::new(),
            };
        }
        use object::read::{Object, ObjectSymbol};
        if !self.language().starts_with("ARM:") {
            return Vec::new();
        }
        let Ok(file) = object::File::parse(self.bytes.as_slice()) else {
            return Vec::new();
        };
        let mut hints = Vec::new();
        // An ELF's or a PE's entry carries the mode in its low bit; a
        // Mach-O's entry is a file offset, and says nothing here.
        let format = file.format();
        let entry = file.entry();
        if entry != 0 && matches!(format, object::BinaryFormat::Elf | object::BinaryFormat::Pe) {
            hints.push((entry & !1, entry & 1 == 1));
        }
        for symbol in file.symbols() {
            let Ok(name) = symbol.name() else { continue };
            // A mapping symbol is `$t` or `$a`, with a `.suffix` at times.
            match name.split('.').next().unwrap_or(name) {
                "$t" => hints.push((symbol.address(), true)),
                "$a" => hints.push((symbol.address(), false)),
                _ => {
                    // An ELF function symbol says its mode in its low bit,
                    // Thumb or ARM; a Mach-O marks Thumb elsewhere, so its
                    // even symbols say nothing.
                    if symbol.kind() == object::SymbolKind::Text {
                        if symbol.address() & 1 == 1 {
                            hints.push((symbol.address() & !1, true));
                        } else if format == object::BinaryFormat::Elf {
                            hints.push((symbol.address(), false));
                        }
                    }
                }
            }
        }
        hints.sort();
        hints.dedup();
        hints
    }

    /// The address the image is loaded at, as its format states it: a PE's
    /// image base, else the page of the lowest segment the file holds bytes
    /// for — an ELF's first `PT_LOAD`, a Mach-O's `__TEXT`. An image whose
    /// format says nothing of the kind — an object file — has none.
    pub fn load_base(&self) -> Option<u64> {
        if let Loaded::Raw(spec) = &self.inner {
            return Some(spec.base);
        }
        use object::read::{Object, ObjectSegment};
        let file = object::File::parse(self.bytes.as_slice()).ok()?;
        if file.format() == object::BinaryFormat::Pe {
            return Some(file.relative_address_base());
        }
        file.segments()
            .filter(|segment| segment.size() > 0 && segment.file_range().1 > 0)
            .map(|segment| segment.address() & !0xfff)
            .min()
    }

    /// The SLEIGH language id the loader resolved, such as `x86:LE:64:default:gcc`.
    pub fn language(&self) -> String {
        match &self.inner {
            Loaded::Object(inner) => String::from_utf8_lossy(inner.arch_id()).into_owned(),
            Loaded::Raw(spec) => spec.language.clone(),
        }
    }

    /// The container's declared entry point, when it declares one.
    pub fn entry(&self) -> Option<u64> {
        match &self.inner {
            Loaded::Object(inner) => inner.image_entry(),
            Loaded::Raw(spec) => spec.entry,
        }
    }

    /// The named sections, in the container's order.
    pub fn sections(&self) -> Vec<Section> {
        let inner = match &self.inner {
            Loaded::Object(inner) => inner,
            // Raw bytes are one section of code, named for what they are.
            Loaded::Raw(spec) => {
                return vec![Section {
                    name: "raw".to_string(),
                    vma: spec.base,
                    size: spec.length.unwrap_or(0),
                    executable: true,
                    file_offset: Some(spec.offset),
                    file_size: spec.length,
                }];
            }
        };
        let executable = inner.executable_ranges();
        inner
            .section_metadata()
            .iter()
            .map(|meta| Section {
                name: meta.name.clone(),
                vma: meta.vma,
                size: meta.size,
                executable: executable
                    .iter()
                    .any(|&(vma, size)| vma == meta.vma && size == meta.size),
                file_offset: meta.file_offset,
                file_size: meta.file_size,
            })
            .collect()
    }

    /// The executable `(vma, size)` extents.
    pub fn executable_ranges(&self) -> Vec<(u64, u64)> {
        match &self.inner {
            Loaded::Object(inner) => inner.executable_ranges(),
            Loaded::Raw(spec) => vec![(spec.base, spec.length.unwrap_or(0))],
        }
    }

    /// The function symbols as `(address, name)`, rebased to the load address.
    pub fn function_symbols(&self) -> Vec<(u64, String)> {
        self.object()
            .map(|inner| inner.func_symbols())
            .unwrap_or_default()
    }

    /// The named data objects as `(address, name, size)`.
    pub fn data_symbols(&self) -> Vec<(u64, String, u64)> {
        self.object()
            .map(|inner| inner.data_symbols())
            .unwrap_or_default()
    }

    /// The name of the function symbol at `address`, when there is one.
    pub fn function_name(&self, address: u64) -> Option<String> {
        self.function_symbols()
            .into_iter()
            .find(|(vma, _)| *vma == address)
            .map(|(_, name)| name)
    }

    /// The import slots of an x86 ELF as `(slot, name)`: the GOT entries the
    /// run-time loader fills with the address of a named symbol, by a
    /// `GLOB_DAT` or `JUMP_SLOT` dynamic relocation.
    ///
    /// A PLT stub is `jmp [rip+slot]`, and a call through the GOT is
    /// `mov rax, [rip+slot]; call rax`; this is what names the function at
    /// the other end. Only these two relocation kinds are read: a `COPY`
    /// relocation fills its slot with the symbol's bytes, not its address,
    /// and a `RELATIVE` one names no symbol. Empty for every other
    /// container and architecture.
    pub fn import_slots(&self) -> Vec<(u64, String)> {
        if self.object().is_none() {
            return Vec::new();
        }
        use object::read::{Object, ObjectSymbol, ObjectSymbolTable};
        use object::{Architecture, RelocationFlags, RelocationTarget};

        let Ok(file) = object::File::parse(self.bytes.as_slice()) else {
            return Vec::new();
        };
        if !matches!(
            file.architecture(),
            Architecture::X86_64 | Architecture::I386
        ) {
            return Vec::new();
        }
        let (Some(relocations), Some(symbols)) =
            (file.dynamic_relocations(), file.dynamic_symbol_table())
        else {
            return Vec::new();
        };

        let mut slots = Vec::new();
        for (slot, relocation) in relocations {
            // R_X86_64_GLOB_DAT and R_X86_64_JUMP_SLOT; the i386 numbers are
            // the same.
            let RelocationFlags::Elf { r_type } = relocation.flags() else {
                continue;
            };
            if r_type != object::elf::R_X86_64_GLOB_DAT && r_type != object::elf::R_X86_64_JUMP_SLOT
            {
                continue;
            }
            if relocation.addend() != 0 {
                continue;
            }
            let RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Ok(symbol) = symbols.symbol_by_index(index) else {
                continue;
            };
            let Ok(name) = symbol.name() else {
                continue;
            };
            if !name.is_empty() {
                slots.push((slot, name.to_string()));
            }
        }
        slots.sort_by_key(|(slot, _)| *slot);
        slots
    }

    /// The file-backed bytes of the section containing `vma`, from `vma` to the
    /// end of what the file holds for it.
    ///
    /// `None` when no section contains `vma` or the section has no bytes in
    /// the file (`.bss`).
    pub fn bytes_from(&self, vma: u64) -> Option<&[u8]> {
        let section = self
            .sections()
            .into_iter()
            .find(|s| s.vma <= vma && vma < s.vma.saturating_add(s.size))?;
        let offset = section.file_offset?;
        let held = section.file_size.unwrap_or(section.size);
        let skip = vma - section.vma;
        if skip >= held {
            return None;
        }
        let start = usize::try_from(offset.checked_add(skip)?).ok()?;
        let end = usize::try_from(offset.checked_add(held)?).ok()?;
        self.bytes.get(start..end)
    }

    /// The bytes of the whole section containing `vma`, with the section.
    pub fn section_bytes(&self, vma: u64) -> Option<(Section, &[u8])> {
        let section = self
            .sections()
            .into_iter()
            .find(|s| s.vma <= vma && vma < s.vma.saturating_add(s.size))?;
        let bytes = self.bytes_from(section.vma)?;
        Some((section, bytes))
    }
}
