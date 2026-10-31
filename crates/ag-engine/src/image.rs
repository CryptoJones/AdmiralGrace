//! A loaded program image: the bytes, sections, entry point and symbols of an
//! ELF, PE, COFF or Mach-O file.
//!
//! The parsing is done by [`kuna_analysis`], the loader and analyzer tier of
//! the kuna decompiler, adopted as a pinned git dependency (see
//! `docs/KUNA_CRATES_EVALUATION.md`). This module is the engine's view of it:
//! enough to pick a code section, hand its bytes to the decoder, and name what
//! the walk finds.

use std::collections::BTreeMap;
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
    /// The slice of a universal Mach-O the bytes are, when they are one:
    /// the file's offsets are the slice's, this far into the file.
    slice: Option<Slice>,
    /// The Objective-C metadata the image carries, read once when asked.
    objc: std::cell::OnceCell<Option<crate::objc::ObjcMetadata>>,
    /// The mangled names the symbol table spells, by address, with what
    /// each demangles to; read once when asked.
    mangled: std::cell::OnceCell<BTreeMap<u64, MangledName>>,
}

/// A mangled name the symbol table spells, and what it demangles to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MangledName {
    /// The symbol as the table spells it: `_ZN8geometry4areaEii`.
    pub mangled: String,
    /// The name the source spelled, signature kept: `geometry::area(int, int)`.
    pub plain: String,
}

/// One slice of a universal (fat) Mach-O: an image of one architecture
/// among several in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slice {
    /// The architecture, as `lipo` names it: `x86_64`, `arm64`, `arm64e`,
    /// `i386`, `arm`.
    pub arch: String,
    /// Where the slice starts in the file.
    pub offset: u64,
    /// How many bytes it is.
    pub size: u64,
}

/// The slice `selector` names among `slices`: an architecture, by name and
/// whatever its case — the first of that name when there are two — or a
/// position counted from 0.
pub fn resolve_slice<'a>(slices: &'a [Slice], selector: &str) -> Option<&'a Slice> {
    let wanted = selector.trim();
    slices
        .iter()
        .find(|found| found.arch.eq_ignore_ascii_case(wanted))
        .or_else(|| {
            wanted
                .parse::<usize>()
                .ok()
                .and_then(|index| slices.get(index))
        })
}

/// The slices of a universal Mach-O, when `bytes` are one; `None` for any
/// other file, a thin Mach-O included.
pub fn fat_slices(bytes: &[u8]) -> Option<Vec<Slice>> {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
    fn name(cputype: u32, cpusubtype: u32) -> String {
        match cputype {
            // Haswell builds carry the subtype 8, and sit beside the plain
            // slice in the same file: they get their own name.
            object::macho::CPU_TYPE_X86_64 if cpusubtype & 0xff == 8 => "x86_64h".to_string(),
            object::macho::CPU_TYPE_X86_64 => "x86_64".to_string(),
            object::macho::CPU_TYPE_X86 => "i386".to_string(),
            object::macho::CPU_TYPE_ARM64 => {
                if cpusubtype & 0xff == object::macho::CPU_SUBTYPE_ARM64E {
                    "arm64e".to_string()
                } else {
                    "arm64".to_string()
                }
            }
            object::macho::CPU_TYPE_ARM => "arm".to_string(),
            other => format!("cputype-{other:#x}"),
        }
    }
    if let Ok(fat) = MachOFatFile32::parse(bytes) {
        return Some(
            fat.arches()
                .iter()
                .map(|arch| Slice {
                    arch: name(arch.cputype(), arch.cpusubtype()),
                    offset: u64::from(arch.offset()),
                    size: u64::from(arch.size()),
                })
                .collect(),
        );
    }
    if let Ok(fat) = MachOFatFile64::parse(bytes) {
        return Some(
            fat.arches()
                .iter()
                .map(|arch| Slice {
                    arch: name(arch.cputype(), arch.cpusubtype()),
                    offset: arch.offset(),
                    size: arch.size(),
                })
                .collect(),
        );
    }
    None
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

/// The architectures raw bytes are read as: the word the command line and
/// the workbench spell each by, and the language id it stands for.
const RAW_ARCHITECTURE_TABLE: &[(&str, &str)] = &[
    ("x86-64", "x86:LE:64:default:gcc"),
    ("x86", "x86:LE:32:default:gcc"),
    ("arm", "ARM:LE:32:v8:default"),
    // Cortex-M: Thumb throughout, under the ARMv7 specification.
    ("thumb", "ARM:LE:32:Cortex:default"),
    ("aarch64", "AARCH64:LE:64:v8A:default"),
];

/// The language id an architecture's name stands for, as the command line
/// and the workbench spell it: `x86-64`, `x86`, `arm`, `thumb`, `aarch64`,
/// and the usual other spellings of each.
pub fn raw_language(arch: &str) -> Option<&'static str> {
    let word = match arch.trim().to_ascii_lowercase().as_str() {
        "x86-64" | "x86_64" | "x64" | "amd64" => "x86-64",
        "x86" | "x86-32" | "i386" | "i686" => "x86",
        "arm" | "arm32" | "armv7" => "arm",
        "thumb" | "cortex" | "cortex-m" => "thumb",
        "aarch64" | "arm64" => "aarch64",
        _ => return None,
    };
    RAW_ARCHITECTURE_TABLE
        .iter()
        .find(|(name, _)| *name == word)
        .map(|(_, language)| *language)
}

/// The architecture's name a raw language id stands for: what the project
/// file records. Only the ids [`raw_language`] hands out have one.
pub fn raw_arch(language: &str) -> Option<&'static str> {
    RAW_ARCHITECTURE_TABLE
        .iter()
        .find(|(_, known)| *known == language)
        .map(|(name, _)| *name)
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
        // A universal Mach-O is several images in one file: which one is
        // the analyst's to say.
        if let Some(slices) = fat_slices(&bytes) {
            anyhow::bail!(
                "{name} is a universal Mach-O with the slices {}: say which one to read",
                slices
                    .iter()
                    .map(|slice| slice.arch.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Image::from_bytes(&name, bytes)
    }

    /// Read one slice of the universal Mach-O at `path`: the one whose
    /// architecture `slice` names — `arm64`, `x86_64` — or whose position
    /// it is, counted from 0. A file that is not universal has no slices to
    /// choose from, and is refused with that said.
    pub fn open_slice(path: &Path, slice: &str) -> Result<Image> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let slices = fat_slices(&bytes)
            .with_context(|| format!("{name} is not a universal Mach-O: it has no slices"))?;
        let chosen = resolve_slice(&slices, slice).with_context(|| {
            format!(
                "{name} has no slice {:?}; its slices are {}",
                slice.trim(),
                slices
                    .iter()
                    .enumerate()
                    .map(|(index, slice)| format!("{index}: {}", slice.arch))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        let start = usize::try_from(chosen.offset).ok();
        let end = start.and_then(|start| {
            usize::try_from(chosen.size)
                .ok()
                .and_then(|size| start.checked_add(size))
        });
        let slice_bytes = start
            .zip(end)
            .and_then(|(start, end)| bytes.get(start..end))
            .with_context(|| {
                format!(
                    "the {} slice of {name} runs past the end of the file",
                    chosen.arch
                )
            })?
            .to_vec();
        let mut image = Image::from_bytes(&format!("{name} ({})", chosen.arch), slice_bytes)?;
        image.slice = Some(chosen.clone());
        Ok(image)
    }

    /// The slice of a universal Mach-O this image is, when it is one.
    pub fn slice(&self) -> Option<&Slice> {
        self.slice.as_ref()
    }

    /// Parse an image already in memory; `name` labels it in errors.
    pub fn from_bytes(name: &str, bytes: Vec<u8>) -> Result<Image> {
        let inner = ObjectLoadImage::from_bytes(name, &bytes)
            .map_err(|error| anyhow::anyhow!("loading {name}: {error}"))?;
        Ok(Image {
            inner: Loaded::Object(Box::new(inner)),
            bytes,
            name: name.to_string(),
            slice: None,
            objc: std::cell::OnceCell::new(),
            mangled: std::cell::OnceCell::new(),
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
            length > 0,
            "there are no bytes to read at the offset {:#x}",
            spec.offset
        );
        // Address 0 is where nothing is mapped, to every reader of the
        // image: bytes said to load there would be read as unmapped.
        anyhow::ensure!(
            spec.base != 0,
            "raw bytes cannot load at address 0: say a base above it"
        );
        // The bytes have to fit the address space of the architecture: a
        // 32-bit program's ends at 4 GiB.
        let top = crate::arch::Bitness::of_language(&spec.language)
            .map_or(u128::from(u64::MAX) + 1, |width| 1u128 << width.bits());
        anyhow::ensure!(
            spec.base.checked_add(length).is_some()
                && u128::from(spec.base) + u128::from(length) <= top,
            "{length} bytes at {:#x} run past the top of the program's address space",
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
            slice: None,
            objc: std::cell::OnceCell::new(),
            mangled: std::cell::OnceCell::new(),
        })
    }

    /// The Objective-C metadata the image carries — its classes, categories
    /// and protocols — when it is a Mach-O with any.
    pub fn objc(&self) -> Option<&crate::objc::ObjcMetadata> {
        self.objc
            .get_or_init(|| self.object().and_then(|_| crate::objc::read(&self.bytes)))
            .as_ref()
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
        let mut symbols = self
            .object()
            .map(|inner| inner.func_symbols())
            .unwrap_or_default();
        self.show_demangled(symbols.iter_mut().map(|(address, name)| (*address, name)));
        // An Objective-C method's implementation is named by the metadata —
        // `-[Class sel]` — where no symbol names it, as in a stripped image.
        // Only an implementation in code is a function: a crafted record
        // pointing into data or off the map names nothing.
        if let Some(objc) = self.objc() {
            let named: std::collections::HashSet<u64> =
                symbols.iter().map(|(address, _)| *address).collect();
            let code: Vec<(u64, u64)> = self
                .sections()
                .into_iter()
                .filter(|section| section.executable)
                .map(|section| (section.vma, section.vma.saturating_add(section.size)))
                .collect();
            for (imp, name) in objc.method_names() {
                let in_code = code
                    .iter()
                    .any(|(start, end)| (*start..*end).contains(&imp));
                if in_code && !named.contains(&imp) {
                    symbols.push((imp, name));
                }
            }
            symbols.sort_by_key(|(address, _)| *address);
        }
        symbols
    }

    /// The named data objects as `(address, name, size)`.
    pub fn data_symbols(&self) -> Vec<(u64, String, u64)> {
        let mut symbols = self
            .object()
            .map(|inner| inner.data_symbols())
            .unwrap_or_default();
        self.show_demangled(symbols.iter_mut().map(|(address, name, _)| (*address, name)));
        // A class object is data the loader registers, named by its class.
        if let Some(objc) = self.objc() {
            let named: std::collections::HashSet<u64> =
                symbols.iter().map(|(address, _, _)| *address).collect();
            for (address, name) in objc.class_symbols() {
                if !named.contains(&address) {
                    symbols.push((address, name, crate::objc::ObjcMetadata::CLASS_OBJECT_SIZE));
                }
            }
            symbols.sort_by_key(|(address, _, _)| *address);
        }
        symbols
    }

    /// Give each named thing the full demangled form of the mangled name
    /// the symbol table spells for its address, where it spells one: the
    /// loader's names are the scope and the name alone, under which two
    /// overloads read the same.
    fn show_demangled<'n>(&self, names: impl Iterator<Item = (u64, &'n mut String)>) {
        let mangled = self.mangled_names();
        if mangled.is_empty() {
            return;
        }
        for (address, name) in names {
            if let Some(found) = mangled.get(&address) {
                *name = found.plain.clone();
            }
        }
    }

    /// The mangled names the symbol table — and a PE's export table —
    /// spells, by address, each with what it demangles to: the C++ and Rust
    /// symbols of the image. Empty for an image with none.
    pub fn mangled_names(&self) -> &BTreeMap<u64, MangledName> {
        self.mangled.get_or_init(|| {
            use object::read::{Object, ObjectSymbol};
            let mut names = BTreeMap::new();
            if self.object().is_none() {
                return names;
            }
            let Ok(file) = object::File::parse(self.bytes.as_slice()) else {
                return names;
            };
            let mut note = |address: u64, name: &str| {
                if address == 0 || names.contains_key(&address) {
                    return;
                }
                if let Some(plain) = crate::demangle::demangle(name) {
                    names.insert(
                        address,
                        MangledName {
                            mangled: name.to_string(),
                            plain,
                        },
                    );
                }
            };
            for symbol in file.symbols().chain(file.dynamic_symbols()) {
                if !symbol.is_definition() {
                    continue;
                }
                if let Ok(name) = symbol.name() {
                    note(symbol.address(), name);
                }
            }
            if let Ok(exports) = file.exports() {
                for export in exports {
                    if let Ok(name) = std::str::from_utf8(export.name()) {
                        note(export.address(), name);
                    }
                }
            }
            names
        })
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
