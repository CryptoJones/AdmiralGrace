//! Microsoft PDB (Program Database) reader and symbol server fetcher (#400).
//!
//! Reads a `.pdb` file's PDBI, DBI, TPI, IPI, global symbols, and per-module
//! symbol and line-program streams into [`PdbInfo`]: functions (with C
//! prototypes, source locations, and stack/register locals), global/static data
//! symbols, and C type definitions in dependency order.
//!
//! [`symsrv`] extracts CodeView `RSDS` identities from PE images and resolves
//! or downloads matching PDBs from sibling files, local caches, or symbol
//! servers (`http://`, `https://`, or directory stores).

pub mod regs;
pub mod symsrv;
pub mod types;

use std::collections::{BTreeMap, BTreeSet};

use pdb::{FallibleIterator, MachineType, SymbolData, TypeIndex};

use crate::types::DataModel;
use types::{is_c_identifier, TypeCatalog};

/// Where a local variable lives inside its function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalLocation {
    /// Stack slot relative to the function's entry stack pointer (`entry_sp + offset`),
    /// matching [`crate::stack_vars::StackVar`].
    Stack { offset: i64, size: u32 },
    /// Machine register (`rax`, `ecx`, `xmm0`, etc.).
    Register { register: String, size: Option<u32> },
}

/// One local variable or parameter recovered for a procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbLocal {
    /// Variable name as spelled in the PDB.
    pub name: String,
    /// Where the variable lives.
    pub location: LocalLocation,
    /// C type string, when the PDB type maps to plain C.
    pub ctype: Option<String>,
    /// Whether the PDB marked this symbol as a function parameter.
    pub is_param: bool,
}

/// One function recovered from the PDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbFunction {
    /// Relative virtual address (RVA) from the PE image base.
    pub rva: u64,
    /// Function byte length, when known from `S_GPROC32`/`S_LPROC32`.
    pub size: Option<u64>,
    /// Name (demangled when mangled).
    pub name: String,
    /// Raw name as recorded in the PDB.
    pub raw_name: String,
    /// C prototype (`int add(int a, int b)`), when available.
    pub prototype: Option<String>,
    /// First source location (`file.c:42`), when present in the line program.
    pub source: Option<String>,
    /// Local variables recovered inside the procedure scope.
    pub locals: Vec<PdbLocal>,
}

/// One data symbol recovered from the PDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbData {
    /// Relative virtual address (RVA) from the PE image base.
    pub rva: u64,
    /// Name (demangled when mangled).
    pub name: String,
    /// Raw name as recorded in the PDB.
    pub raw_name: String,
    /// Size in bytes, when known from its type.
    pub size: Option<u64>,
    /// C type string, when available.
    pub ctype: Option<String>,
}

/// Complete extracted contents of a PDB file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PdbInfo {
    /// Canonical 32-character uppercase hex GUID.
    pub guid: String,
    /// PDB age counter (DBI age when available, else PDBI age).
    pub age: u32,
    /// PDBI timestamp signature.
    pub signature: u32,
    /// Symbol server lookup identifier (`<GUID><age:x>`).
    pub id: String,
    /// Human-readable machine name (`x86`, `x64`, `arm64`, etc.).
    pub machine: String,
    /// Raw COFF machine code (`0x14c`, `0x8664`, ...).
    pub machine_raw: u16,
    /// Number of modules in the DBI stream.
    pub modules_count: usize,
    /// Functions recovered (sorted by RVA).
    pub functions: Vec<PdbFunction>,
    /// Global/static data symbols recovered (sorted by RVA).
    pub data: Vec<PdbData>,
    /// C type definitions in dependency order.
    pub types: Vec<String>,
    /// Count of PDB types held back because they have no plain C representation.
    pub types_held_back: usize,
    /// Notes about skipped or held-back items.
    pub notes: Vec<String>,
}

/// Default data model implied by a PDB machine type.
pub fn data_model_for_machine(machine_raw: u16) -> DataModel {
    match machine_raw {
        regs::MACHINE_X86 | 0x1c0 | 0x1c4 => DataModel {
            wchar: 2,
            ..DataModel::ILP32
        },
        _ => DataModel::LLP64,
    }
}

/// Parse a PDB byte slice into [`PdbInfo`].
/// If `model` is `None`, the data model is inferred from the DBI machine type.
pub fn read_pdb(bytes: &[u8], model: Option<DataModel>) -> Result<PdbInfo, String> {
    let mut pdb = pdb::PDB::open(std::io::Cursor::new(bytes))
        .map_err(|e| format!("opening PDB: {e}"))?;

    let pdbi = pdb
        .pdb_information()
        .map_err(|e| format!("reading PDB information stream: {e}"))?;
    let guid = symsrv::format_pdb_guid(pdbi.guid);
    let signature = pdbi.signature;

    let dbi = pdb
        .debug_information()
        .map_err(|e| format!("reading PDB DBI stream: {e}"))?;
    let machine_type = dbi.machine_type().unwrap_or(MachineType::Unknown);
    let machine_raw = machine_type_raw(machine_type);
    let machine = machine_label(machine_type);
    let age = dbi.age().unwrap_or(pdbi.age);
    let id = format!("{guid}{age:x}");
    let model = model.unwrap_or_else(|| data_model_for_machine(machine_raw));

    let addr_map = pdb
        .address_map()
        .map_err(|e| format!("reading PDB address map: {e}"))?;
    let tpi = pdb
        .type_information()
        .map_err(|e| format!("reading PDB type stream: {e}"))?;
    let ipi = pdb.id_information().ok();
    let strings = pdb.string_table().ok();
    let catalog = TypeCatalog::build(&tpi, ipi.as_ref(), model)?;

    let mut functions: BTreeMap<u64, PdbFunction> = BTreeMap::new();
    let mut data: BTreeMap<u64, PdbData> = BTreeMap::new();
    let mut udts: Vec<(String, TypeIndex)> = Vec::new();
    let mut modules_count = 0usize;

    let mut modules = dbi
        .modules()
        .map_err(|e| format!("reading PDB modules: {e}"))?;
    while let Some(module) = modules
        .next()
        .map_err(|e| format!("iterating PDB modules: {e}"))?
    {
        modules_count += 1;
        let Some(info) = pdb
            .module_info(&module)
            .map_err(|e| format!("reading module info: {e}"))?
        else {
            continue;
        };

        let line_program = info.line_program().ok();
        let mut sym_iter = match info.symbols() {
            Ok(iter) => iter,
            Err(_) => continue,
        };

        let mut scope_stack: Vec<ScopeFrame> = Vec::new();
        let mut pending_local: Option<PendingLocal> = None;

        while let Some(sym) = sym_iter
            .next()
            .map_err(|e| format!("reading module symbol: {e}"))?
        {
            let kind = sym.raw_kind();
            match sym.parse() {
                Ok(SymbolData::Procedure(proc)) => {
                    pending_local = None;
                    let rva = proc.offset.to_rva(&addr_map).map(|r| u64::from(r.0));
                    let raw_name = proc.name.to_string().into_owned();
                    let name = plain_name(&raw_name);
                    let source = line_program
                        .as_ref()
                        .and_then(|lp| {
                            source_for_offset(lp, proc.offset, strings.as_ref())
                        });
                    let is_id = matches!(
                        kind,
                        S_GPROC32_ID | S_LPROC32_ID | S_LPROC32_DPC_ID
                    );
                    scope_stack.push(ScopeFrame::Procedure {
                        rva,
                        size: u64::from(proc.len),
                        name,
                        raw_name,
                        type_index: proc.type_index,
                        is_id,
                        source,
                        frame_size: None,
                        param_names: Vec::new(),
                        locals: Vec::new(),
                        seen_stack_offsets: BTreeSet::new(),
                    });
                }
                Ok(SymbolData::Block(_))
                | Ok(SymbolData::Thunk(_))
                | Ok(SymbolData::SeparatedCode(_)) => {
                    pending_local = None;
                    scope_stack.push(ScopeFrame::Other);
                }
                Ok(SymbolData::InlineSite(_)) => {
                    pending_local = None;
                    scope_stack.push(ScopeFrame::InlineSite);
                }
                Ok(SymbolData::ScopeEnd)
                | Ok(SymbolData::ProcedureEnd)
                | Ok(SymbolData::InlineSiteEnd) => {
                    pending_local = None;
                    if let Some(ScopeFrame::Procedure {
                        rva: Some(rva),
                        size,
                        name,
                        raw_name,
                        type_index,
                        is_id,
                        source,
                        param_names,
                        locals,
                        ..
                    }) = scope_stack.pop()
                    {
                        let prototype = catalog.render_prototype(
                            type_index,
                            is_id,
                            &name,
                            &param_names,
                        );
                        functions.entry(rva).or_insert(PdbFunction {
                            rva,
                            size: (size > 0).then_some(size),
                            name,
                            raw_name,
                            prototype,
                            source,
                            locals,
                        });
                    }
                }
                Ok(SymbolData::Local(loc)) => {
                    let lname = loc.name.to_string().into_owned();
                    let in_inline = scope_stack
                        .iter()
                        .any(|s| matches!(s, ScopeFrame::InlineSite));
                    if !in_inline {
                        if let Some(proc) = current_procedure_mut(&mut scope_stack) {
                            if loc.flags.isparam {
                                proc.push_param_name(&lname);
                            }
                            pending_local = Some(PendingLocal {
                                name: lname,
                                type_index: loc.type_index,
                                is_param: loc.flags.isparam,
                            });
                        }
                    } else {
                        pending_local = None;
                    }
                }
                Ok(SymbolData::RegisterRelative(rr)) => {
                    pending_local = None;
                    let in_inline = scope_stack
                        .iter()
                        .any(|s| matches!(s, ScopeFrame::InlineSite));
                    if in_inline {
                        continue;
                    }
                    let Some(proc) = current_procedure_mut(&mut scope_stack) else {
                        continue;
                    };
                    let vname = rr.name.to_string().into_owned();
                    let Some(entry_offset) = resolve_stack_offset(
                        machine_raw,
                        rr.register.0,
                        rr.offset,
                        proc.frame_size(),
                    ) else {
                        continue;
                    };
                    if entry_offset > 0 {
                        proc.push_param_name(&vname);
                        continue;
                    }
                    if entry_offset < 0 && is_c_identifier(&vname) {
                        let size = catalog
                            .type_size(rr.type_index)
                            .and_then(|s| u32::try_from(s).ok())
                            .unwrap_or(0);
                        if size > 0 && proc.insert_stack_offset(entry_offset) {
                            let ctype = catalog.render_type(rr.type_index);
                            proc.push_local(PdbLocal {
                                name: vname,
                                location: LocalLocation::Stack {
                                    offset: entry_offset,
                                    size,
                                },
                                ctype,
                                is_param: false,
                            });
                        }
                    }
                }
                Ok(SymbolData::RegisterVariable(rv)) => {
                    pending_local = None;
                    let in_inline = scope_stack
                        .iter()
                        .any(|s| matches!(s, ScopeFrame::InlineSite));
                    if in_inline {
                        continue;
                    }
                    let Some(proc) = current_procedure_mut(&mut scope_stack) else {
                        continue;
                    };
                    let vname = rv.name.to_string().into_owned();
                    let Some(reg) = regs::name(machine_raw, rv.register.0) else {
                        continue;
                    };
                    if is_c_identifier(&vname) {
                        let size = catalog
                            .type_size(rv.type_index)
                            .and_then(|s| u32::try_from(s).ok());
                        let ctype = catalog.render_type(rv.type_index);
                        proc.push_local(PdbLocal {
                            name: vname,
                            location: LocalLocation::Register {
                                register: reg.to_string(),
                                size,
                            },
                            ctype,
                            is_param: false,
                        });
                    }
                }
                Ok(SymbolData::Data(d)) => {
                    pending_local = None;
                    if let Some(rva) = d.offset.to_rva(&addr_map).map(|r| u64::from(r.0)) {
                        let raw_name = d.name.to_string().into_owned();
                        let name = plain_name(&raw_name);
                        let size = catalog.type_size(d.type_index);
                        let ctype = catalog.render_type(d.type_index);
                        data.entry(rva).or_insert(PdbData {
                            rva,
                            name,
                            raw_name,
                            size,
                            ctype,
                        });
                    }
                }
                Ok(SymbolData::UserDefinedType(u)) => {
                    pending_local = None;
                    udts.push((u.name.to_string().into_owned(), u.type_index));
                }
                Ok(_) => {
                    pending_local = None;
                }
                Err(pdb::Error::UnimplementedSymbolKind(raw_kind)) => {
                    let raw = sym.raw_bytes();
                    match raw_kind {
                        S_FRAMEPROC => {
                            if raw.len() >= 6 {
                                let cb_frame =
                                    u32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]);
                                if let Some(proc) = current_procedure_mut(&mut scope_stack) {
                                    proc.set_frame_size(cb_frame);
                                }
                            }
                        }
                        S_DEFRANGE_FRAMEPOINTER_REL | S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE => {
                            if let (Some(local), Some(proc)) = (
                                pending_local.take(),
                                current_procedure_mut(&mut scope_stack),
                            ) {
                                if !local.is_param && raw.len() >= 6 && is_c_identifier(&local.name)
                                {
                                    let fp_offset =
                                        i32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]);
                                    if let Some(bias) = regs::frame_bias(machine_raw) {
                                        let entry_offset = i64::from(fp_offset) - bias;
                                        let size = catalog
                                            .type_size(local.type_index)
                                            .and_then(|s| u32::try_from(s).ok())
                                            .unwrap_or(0);
                                        if entry_offset < 0
                                            && size > 0
                                            && proc.insert_stack_offset(entry_offset)
                                        {
                                            let ctype = catalog.render_type(local.type_index);
                                            proc.push_local(PdbLocal {
                                                name: local.name,
                                                location: LocalLocation::Stack {
                                                    offset: entry_offset,
                                                    size,
                                                },
                                                ctype,
                                                is_param: false,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        S_DEFRANGE_REGISTER => {
                            if let (Some(local), Some(proc)) = (
                                pending_local.take(),
                                current_procedure_mut(&mut scope_stack),
                            ) {
                                if !local.is_param && raw.len() >= 4 && is_c_identifier(&local.name)
                                {
                                    let reg_num = u16::from_le_bytes([raw[2], raw[3]]);
                                    if let Some(reg) = regs::name(machine_raw, reg_num) {
                                        let size = catalog
                                            .type_size(local.type_index)
                                            .and_then(|s| u32::try_from(s).ok());
                                        let ctype = catalog.render_type(local.type_index);
                                        proc.push_local(PdbLocal {
                                            name: local.name,
                                            location: LocalLocation::Register {
                                                register: reg.to_string(),
                                                size,
                                            },
                                            ctype,
                                            is_param: false,
                                        });
                                    }
                                }
                            }
                        }
                        S_DEFRANGE_REGISTER_REL => {
                            if let (Some(local), Some(proc)) = (
                                pending_local.take(),
                                current_procedure_mut(&mut scope_stack),
                            ) {
                                if !local.is_param
                                    && raw.len() >= 10
                                    && is_c_identifier(&local.name)
                                {
                                    let reg_num = u16::from_le_bytes([raw[2], raw[3]]);
                                    let off = i32::from_le_bytes([raw[6], raw[7], raw[8], raw[9]]);
                                    if let Some(entry_offset) = resolve_stack_offset(
                                        machine_raw,
                                        reg_num,
                                        off,
                                        proc.frame_size(),
                                    ) {
                                        let size = catalog
                                            .type_size(local.type_index)
                                            .and_then(|s| u32::try_from(s).ok())
                                            .unwrap_or(0);
                                        if entry_offset < 0
                                            && size > 0
                                            && proc.insert_stack_offset(entry_offset)
                                        {
                                            let ctype = catalog.render_type(local.type_index);
                                            proc.push_local(PdbLocal {
                                                name: local.name,
                                                location: LocalLocation::Stack {
                                                    offset: entry_offset,
                                                    size,
                                                },
                                                ctype,
                                                is_param: false,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            pending_local = None;
                        }
                    }
                }
                Err(_) => {
                    pending_local = None;
                }
            }
        }
    }

    // Global symbols: fill global data, UDT typedefs, and public symbols not
    // already covered by module procedures/data (essential for stripped public PDBs).
    if let Ok(globals) = pdb.global_symbols() {
        let mut iter = globals.iter();
        while let Some(sym) = iter
            .next()
            .map_err(|e| format!("reading global symbols: {e}"))?
        {
            match sym.parse() {
                Ok(SymbolData::Data(d)) => {
                    if let Some(rva) = d.offset.to_rva(&addr_map).map(|r| u64::from(r.0)) {
                        let raw_name = d.name.to_string().into_owned();
                        let name = plain_name(&raw_name);
                        let size = catalog.type_size(d.type_index);
                        let ctype = catalog.render_type(d.type_index);
                        data.entry(rva).or_insert(PdbData {
                            rva,
                            name,
                            raw_name,
                            size,
                            ctype,
                        });
                    }
                }
                Ok(SymbolData::UserDefinedType(u)) => {
                    udts.push((u.name.to_string().into_owned(), u.type_index));
                }
                Ok(SymbolData::Public(p)) => {
                    if let Some(rva) = p.offset.to_rva(&addr_map).map(|r| u64::from(r.0)) {
                        let raw_name = p.name.to_string().into_owned();
                        let name = plain_name(&raw_name);
                        if p.function || p.code {
                            functions.entry(rva).or_insert(PdbFunction {
                                rva,
                                size: None,
                                name,
                                raw_name,
                                prototype: None,
                                source: None,
                                locals: Vec::new(),
                            });
                        } else if !functions.contains_key(&rva) {
                            data.entry(rva).or_insert(PdbData {
                                rva,
                                name,
                                raw_name,
                                size: None,
                                ctype: None,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let (type_defs, types_held_back) = catalog.render_definitions(&udts);
    let types = type_defs.into_iter().map(|t| t.c).collect();

    Ok(PdbInfo {
        guid,
        age,
        signature,
        id,
        machine,
        machine_raw,
        modules_count,
        functions: functions.into_values().collect(),
        data: data.into_values().collect(),
        types,
        types_held_back,
        notes: Vec::new(),
    })
}

const S_FRAMEPROC: u16 = 0x1012;
const S_GPROC32_ID: u16 = 0x1147;
const S_LPROC32_ID: u16 = 0x1146;
const S_LPROC32_DPC_ID: u16 = 0x1156;
const S_DEFRANGE_REGISTER: u16 = 0x1141;
const S_DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
const S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: u16 = 0x1144;
const S_DEFRANGE_REGISTER_REL: u16 = 0x1145;

struct PendingLocal {
    name: String,
    type_index: TypeIndex,
    is_param: bool,
}

enum ScopeFrame {
    Procedure {
        rva: Option<u64>,
        size: u64,
        name: String,
        raw_name: String,
        type_index: TypeIndex,
        is_id: bool,
        source: Option<String>,
        frame_size: Option<u32>,
        param_names: Vec<Option<String>>,
        locals: Vec<PdbLocal>,
        seen_stack_offsets: BTreeSet<i64>,
    },
    InlineSite,
    Other,
}

impl ScopeFrame {
    fn frame_size(&self) -> Option<u32> {
        match self {
            ScopeFrame::Procedure { frame_size, .. } => *frame_size,
            _ => None,
        }
    }

    fn set_frame_size(&mut self, sz: u32) {
        if let ScopeFrame::Procedure { frame_size, .. } = self {
            *frame_size = Some(sz);
        }
    }

    fn push_param_name(&mut self, name: &str) {
        if let ScopeFrame::Procedure { param_names, .. } = self {
            let entry = is_c_identifier(name).then(|| name.to_string());
            param_names.push(entry);
        }
    }

    fn insert_stack_offset(&mut self, offset: i64) -> bool {
        match self {
            ScopeFrame::Procedure {
                seen_stack_offsets, ..
            } => seen_stack_offsets.insert(offset),
            _ => false,
        }
    }

    fn push_local(&mut self, local: PdbLocal) {
        if let ScopeFrame::Procedure { locals, .. } = self {
            locals.push(local);
        }
    }
}

fn current_procedure_mut(stack: &mut [ScopeFrame]) -> Option<&mut ScopeFrame> {
    stack
        .iter_mut()
        .rev()
        .find(|f| matches!(f, ScopeFrame::Procedure { .. }))
}

fn resolve_stack_offset(
    machine_raw: u16,
    register: u16,
    offset: i32,
    frame_size: Option<u32>,
) -> Option<i64> {
    if regs::is_frame_pointer(machine_raw, register) {
        let bias = regs::frame_bias(machine_raw)?;
        Some(i64::from(offset) - bias)
    } else if regs::is_stack_pointer(machine_raw, register) {
        let frame = i64::from(frame_size?);
        if frame == 0 {
            return None;
        }
        Some(i64::from(offset) - frame)
    } else {
        None
    }
}

fn source_for_offset(
    lp: &pdb::LineProgram<'_>,
    offset: pdb::PdbInternalSectionOffset,
    strings: Option<&pdb::StringTable<'_>>,
) -> Option<String> {
    let mut lines = lp.lines_for_symbol(offset);
    let line = lines.next().ok()??;
    let file_info = lp.get_file_info(line.file_index).ok()?;
    let file_name = if let Some(st) = strings {
        st.get(file_info.name)
            .ok()
            .map(|s| s.to_string().into_owned())
    } else {
        None
    }?;
    let base = symsrv::pdb_basename(&file_name);
    Some(format!("{base}:{}", line.line_start))
}

fn plain_name(raw: &str) -> String {
    crate::demangle::demangle(raw).unwrap_or_else(|| raw.to_string())
}

fn machine_type_raw(m: MachineType) -> u16 {
    match m {
        MachineType::Unknown => 0x0,
        MachineType::Am33 => 0x13,
        MachineType::Amd64 => 0x8664,
        MachineType::Arm => 0x1C0,
        MachineType::Arm64 => 0xAA64,
        MachineType::ArmNT => 0x1C4,
        MachineType::Ebc => 0xEBC,
        MachineType::X86 => 0x14C,
        MachineType::Ia64 => 0x200,
        MachineType::M32R => 0x9041,
        MachineType::Mips16 => 0x266,
        MachineType::MipsFpu => 0x366,
        MachineType::MipsFpu16 => 0x466,
        MachineType::PowerPC => 0x1F0,
        MachineType::PowerPCFP => 0x1F1,
        MachineType::R4000 => 0x166,
        MachineType::RiscV32 => 0x5032,
        MachineType::RiscV64 => 0x5064,
        MachineType::RiscV128 => 0x5128,
        MachineType::SH3 => 0x1A2,
        MachineType::SH3DSP => 0x1A3,
        MachineType::SH4 => 0x1A6,
        MachineType::SH5 => 0x1A8,
        MachineType::Thumb => 0x1C2,
        MachineType::WceMipsV2 => 0x169,
        _ => 0x0,
    }
}

fn machine_label(m: MachineType) -> String {
    match m {
        MachineType::X86 => "x86".to_string(),
        MachineType::Amd64 => "x64".to_string(),
        MachineType::Arm => "arm".to_string(),
        MachineType::ArmNT => "thumb".to_string(),
        MachineType::Arm64 => "arm64".to_string(),
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}
