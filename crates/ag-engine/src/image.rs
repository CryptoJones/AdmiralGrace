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
    inner: ObjectLoadImage,
    bytes: Vec<u8>,
    name: String,
}

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
            inner,
            bytes,
            name: name.to_string(),
        })
    }

    /// The name the image was opened under.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The bytes of the file, as read.
    pub fn file_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The address the image is loaded at, as its format states it: a PE's
    /// image base, else the page of the lowest segment the file holds bytes
    /// for — an ELF's first `PT_LOAD`, a Mach-O's `__TEXT`. An image whose
    /// format says nothing of the kind — an object file — has none.
    pub fn load_base(&self) -> Option<u64> {
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
        String::from_utf8_lossy(self.inner.arch_id()).into_owned()
    }

    /// The container's declared entry point, when it declares one.
    pub fn entry(&self) -> Option<u64> {
        self.inner.image_entry()
    }

    /// The named sections, in the container's order.
    pub fn sections(&self) -> Vec<Section> {
        let executable = self.inner.executable_ranges();
        self.inner
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
        self.inner.executable_ranges()
    }

    /// The function symbols as `(address, name)`, rebased to the load address.
    pub fn function_symbols(&self) -> Vec<(u64, String)> {
        self.inner.func_symbols()
    }

    /// The named data objects as `(address, name, size)`.
    pub fn data_symbols(&self) -> Vec<(u64, String, u64)> {
        self.inner.data_symbols()
    }

    /// The name of the function symbol at `address`, when there is one.
    pub fn function_name(&self, address: u64) -> Option<String> {
        self.inner
            .func_symbols()
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
