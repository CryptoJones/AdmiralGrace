//! Import a CMSIS SVD peripheral map (#406).
//!
//! A System View Description file is the XML a microcontroller vendor
//! ships to say what peripherals the device has: each one's base address,
//! the address blocks it decodes, its registers at their offsets, and the
//! fields of each register with the values they take. [`parse`] reads that
//! description into a [`Map`] — the peripherals with their registers
//! resolved: `derivedFrom` inheritance followed, register and peripheral
//! arrays (`dim`) expanded, clusters flattened into member names — and
//! [`struct_c`], [`segments`], [`peripheral_comment`] and
//! [`register_comment`] turn one peripheral into the pieces a project
//! keeps: a C structure of its registers, the segments its address blocks
//! map, and the comments that say what each place is.
//!
//! The XML is read by a small reader of this module's own, for the subset
//! SVD uses: elements, attributes, text, comments, CDATA and the five
//! entities and numeric character references. No tree of another crate is
//! read, so the import works offline with nothing installed.
//!
//! What the file gets wrong is held back rather than guessed at: a
//! peripheral with no base address, or deriving from one the file does not
//! name, is skipped with its reason ([`Skipped`]); a register of a width
//! the C cannot hold, at an offset its width does not align to, or
//! overlapping another, is left out with a note ([`Map::notes`]). The
//! registers a derived peripheral declares itself replace the ones it
//! inherits by name, and add the rest. Fields are read into the register
//! comments — the structure holds whole registers, the widths the SVD
//! gives, not bit-fields, whose layout C leaves to the compiler.

use std::collections::BTreeSet;

/// A peripheral map read from an SVD file: the device, the peripherals
/// that resolved, and what was held back on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Map {
    /// The device's name, as `<name>` spells it.
    pub device: String,
    /// The device's description, when it gives one.
    pub description: String,
    /// The register width in bits the device defaults to: 8, 16, 32 or 64.
    pub width: u32,
    /// The peripherals that resolved, in the order the file declares them.
    pub peripherals: Vec<Peripheral>,
    /// The peripherals held back, each with why.
    pub skipped: Vec<Skipped>,
    /// Notes left on the way through: registers dropped, names mended.
    pub notes: Vec<String>,
}

/// A peripheral held back, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The peripheral's name, as the file spells it.
    pub name: String,
    /// Why it was held back.
    pub reason: String,
}

/// One peripheral of a device, its registers resolved and flattened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peripheral {
    /// Its name: `GPIOA`, `USART1`.
    pub name: String,
    /// Its description, when the file gives one.
    pub description: String,
    /// The group it belongs to (`groupName`), when the file gives one.
    pub group: String,
    /// The address its registers sit at.
    pub base: u64,
    /// The address blocks it decodes, in the file's order; when the file
    /// names none, one block covering the registers is made up.
    pub blocks: Vec<AddressBlock>,
    /// The interrupts it raises, in the file's order.
    pub interrupts: Vec<Interrupt>,
    /// Its registers, flattened and sorted by offset, names unique and
    /// read as C identifiers.
    pub registers: Vec<Register>,
    /// The peripheral it derives from, when it derives from one.
    pub derived_from: Option<String>,
}

/// One address block a peripheral decodes: `size` bytes at `offset` from
/// its base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBlock {
    /// The offset from the peripheral's base.
    pub offset: u64,
    /// The size in bytes.
    pub size: u64,
    /// What the block is for: `registers`, `protection` or `ram`.
    pub usage: String,
}

/// One interrupt a peripheral raises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interrupt {
    /// The interrupt's name.
    pub name: String,
    /// Its number in the device's vector table.
    pub value: u64,
}

/// One register of a peripheral, at its byte offset from the base.
///
/// A register array the SVD declares with `dim` is one entry with `count`
/// elements when they sit packed (`stride` the register's own width), and
/// one entry per element, named with the index, when they do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    /// The member name in the structure: `CRL`, `TIMER_CTRL`, `DATA_0`.
    pub name: String,
    /// The name as the SVD spells it, clusters joined with dots:
    /// `TIMER.CTRL` — what the comment calls it.
    pub display: String,
    /// Its description, when the file gives one.
    pub description: String,
    /// The byte offset from the peripheral's base.
    pub offset: u64,
    /// The width in bits: 8, 16, 32 or 64.
    pub width: u32,
    /// How it is accessed: `read-write`, `read-only`, `write-only`, …
    pub access: String,
    /// The value it resets to, when the file says.
    pub reset: Option<u64>,
    /// Its fields, in the file's order.
    pub fields: Vec<Field>,
    /// How many elements: one for a plain register, the `dim` of a packed
    /// array.
    pub count: u32,
    /// The bytes from one element to the next: the register's width for a
    /// plain register or a packed array, the `dimIncrement` otherwise.
    pub stride: u64,
}

impl Register {
    /// The byte extent of the register: where the next one may sit.
    pub fn span(&self) -> u64 {
        self.stride * u64::from(self.count)
    }
}

/// One field of a register: the bits from `lsb` to `msb`, and the values
/// they take when the file enumerates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The field's name.
    pub name: String,
    /// Its description, when the file gives one.
    pub description: String,
    /// The least significant bit.
    pub lsb: u32,
    /// The most significant bit.
    pub msb: u32,
    /// The values the field takes, in the file's order.
    pub values: Vec<EnumValue>,
}

/// One value a field takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumValue {
    /// The value's name.
    pub name: String,
    /// The value itself.
    pub value: u64,
    /// Its description, when the file gives one.
    pub description: String,
}

/// One segment a peripheral's address block maps: `size` bytes at
/// `address`, holding no bytes of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The segment's name: the peripheral's, numbered past the first when
    /// it decodes more than one block.
    pub name: String,
    /// The address it maps to.
    pub address: u64,
    /// Its size in bytes.
    pub size: u64,
}

/// The name the peripheral's structure goes by: `struct GPIOA`.
pub fn struct_name(peripheral: &Peripheral) -> String {
    format!("struct {}", peripheral.name)
}

/// The bytes the peripheral's structure covers: its registers to the last
/// one's end, or its furthest address block's end when that reaches past
/// them.
pub fn struct_size(peripheral: &Peripheral) -> u64 {
    let registers = peripheral
        .registers
        .iter()
        .map(|r| r.offset + r.span())
        .max()
        .unwrap_or(0);
    let blocks = peripheral
        .blocks
        .iter()
        .map(|b| b.offset + b.size)
        .max()
        .unwrap_or(0);
    registers.max(blocks)
}

/// The peripheral's registers as one C definition: each register a member
/// of its width at its offset, the gaps between them reserved bytes, the
/// whole padded to [`struct_size`]. Every member carries its offset in a
/// comment, as the type store prints layouts.
pub fn struct_c(peripheral: &Peripheral) -> String {
    let mut out = format!("struct {} {{\n", peripheral.name);
    let mut used: BTreeSet<String> = peripheral
        .registers
        .iter()
        .map(|r| r.name.clone())
        .collect();
    let mut at = 0u64;
    for register in &peripheral.registers {
        if register.offset > at {
            out.push_str(&padding(&mut used, at, register.offset - at));
        }
        let ty = width_type(register.width);
        if register.count > 1 {
            out.push_str(&format!(
                "  {ty} {}[{}]; /* {:#x} */\n",
                register.name, register.count, register.offset
            ));
        } else {
            out.push_str(&format!(
                "  {ty} {}; /* {:#x} */\n",
                register.name, register.offset
            ));
        }
        at = register.offset + register.span();
    }
    let end = struct_size(peripheral);
    if end > at {
        out.push_str(&padding(&mut used, at, end - at));
    }
    out.push_str("};");
    out
}

/// The reserved bytes from `at`, `count` of them, named past the names
/// already used.
fn padding(used: &mut BTreeSet<String>, at: u64, count: u64) -> String {
    let base = format!("reserved_{at:x}");
    let mut name = base.clone();
    let mut suffix = 2;
    while used.contains(&name) {
        name = format!("{base}_{suffix}");
        suffix += 1;
    }
    used.insert(name.clone());
    format!("  uint8_t {name}[{count}]; /* {at:#x}: {count} bytes reserved */\n")
}

/// The C type of a register width: the unsigned integer of the size.
fn width_type(width: u32) -> &'static str {
    match width {
        8 => "uint8_t",
        16 => "uint16_t",
        64 => "uint64_t",
        _ => "uint32_t",
    }
}

/// The segments the peripheral's address blocks map. A file that names no
/// block gets one covering the registers; a file that names several gets
/// one each, the first under the peripheral's name and the rest numbered.
pub fn segments(peripheral: &Peripheral) -> Vec<Segment> {
    let blocks: Vec<(u64, u64)> = if peripheral.blocks.is_empty() {
        let size = struct_size(peripheral);
        if size == 0 {
            return Vec::new();
        }
        vec![(0, size)]
    } else {
        peripheral
            .blocks
            .iter()
            .filter(|b| b.size > 0)
            .map(|b| (b.offset, b.size))
            .collect()
    };
    blocks
        .into_iter()
        .enumerate()
        .map(|(index, (offset, size))| Segment {
            name: if index == 0 {
                peripheral.name.clone()
            } else {
                format!("{}_{}", peripheral.name, index)
            },
            address: peripheral.base + offset,
            size,
        })
        .collect()
}

/// The comment the peripheral's base address carries: its name and
/// description, its group, the ranges it decodes and the interrupts it
/// raises, one line.
pub fn peripheral_comment(peripheral: &Peripheral) -> String {
    let mut parts = Vec::new();
    let mut head = peripheral.name.clone();
    if !peripheral.description.is_empty() {
        head.push_str(": ");
        head.push_str(&peripheral.description);
    }
    if !peripheral.group.is_empty() {
        head.push_str(&format!(" (group {})", peripheral.group));
    }
    parts.push(head);
    for block in &peripheral.blocks {
        parts.push(format!(
            "{} {:#x}-{:#x}",
            block.usage,
            peripheral.base + block.offset,
            peripheral.base + block.offset + block.size
        ));
    }
    for interrupt in &peripheral.interrupts {
        parts.push(format!(
            "interrupt {} ({})",
            interrupt.value, interrupt.name
        ));
    }
    parts.join("; ")
}

/// The comment one register's address carries: the register's name and
/// description, its access and reset value, and its fields with their bits
/// and the values they take, one line.
pub fn register_comment(peripheral: &Peripheral, register: &Register) -> String {
    let mut head = format!("{}.{}", peripheral.name, register.display);
    if !register.description.is_empty() {
        head.push_str(": ");
        head.push_str(&register.description);
    }
    let mut facts = vec![register.access.clone()];
    if let Some(reset) = register.reset {
        facts.push(format!("reset {reset:#x}"));
    }
    if register.count > 1 {
        facts.push(format!("{} registers", register.count));
    }
    head.push_str(&format!(" ({})", facts.join(", ")));
    let mut parts = vec![head];
    for field in &register.fields {
        let bits = if field.msb == field.lsb {
            format!("[{}]", field.lsb)
        } else {
            format!("[{}:{}]", field.msb, field.lsb)
        };
        let mut text = format!("{}{bits}", field.name);
        if !field.description.is_empty() {
            text.push_str(": ");
            text.push_str(&field.description);
        }
        if !field.values.is_empty() {
            let values: Vec<String> = field
                .values
                .iter()
                .map(|v| {
                    let value = if v.value < 16 {
                        format!("{}", v.value)
                    } else {
                        format!("{:#x}", v.value)
                    };
                    if v.description.is_empty() {
                        format!("{}={value}", v.name)
                    } else {
                        format!("{}={value} ({})", v.name, v.description)
                    }
                })
                .collect();
            text.push_str(": ");
            text.push_str(&values.join(", "));
        }
        parts.push(text);
    }
    parts.join("; ")
}

/// Read an SVD file's text into a [`Map`]. The file that is not XML, or
/// whose root is not `<device>`, or that names no peripherals, is refused
/// with the reason; a peripheral that does not resolve is held back in
/// [`Map::skipped`] rather than refusing the whole file.
pub fn parse(text: &str) -> Result<Map, String> {
    let root = xml::parse(text)?;
    if root.name != "device" {
        return Err(format!(
            "not an SVD file: the root is <{}>, not <device>",
            root.name
        ));
    }
    let device = root
        .child("name")
        .map(xml::Xml::text)
        .filter(|name| !name.is_empty())
        .ok_or("the device has no <name>")?;
    let description = root
        .child("description")
        .map(xml::Xml::text)
        .unwrap_or_default();
    let mut notes = Vec::new();
    let width = match root.child("width").map(xml::Xml::text) {
        Some(text) => match text.parse::<u32>() {
            Ok(width) if matches!(width, 8 | 16 | 32 | 64) => width,
            _ => {
                notes.push(format!(
                    "the device width {text:?} is not 8, 16, 32 or 64: read as 32"
                ));
                32
            }
        },
        None => 32,
    };
    let peripherals = root
        .child("peripherals")
        .ok_or("the device has no <peripherals>")?;
    let mut map = Map {
        device,
        description,
        width,
        peripherals: Vec::new(),
        skipped: Vec::new(),
        notes,
    };
    let mut resolved: Vec<Peripheral> = Vec::new();
    for element in peripherals.children("peripheral") {
        let name = element
            .child("name")
            .map(xml::Xml::text)
            .unwrap_or_default();
        let name = if name.is_empty() {
            "(unnamed)".to_string()
        } else {
            name
        };
        match peripheral(element, width, &resolved, &mut map.notes) {
            Ok(made) => {
                for peripheral in made {
                    if resolved.iter().any(|held| held.name == peripheral.name)
                        || map
                            .peripherals
                            .iter()
                            .any(|held| held.name == peripheral.name)
                    {
                        map.skipped.push(Skipped {
                            name: peripheral.name,
                            reason: "another peripheral has the name already".into(),
                        });
                        continue;
                    }
                    resolved.push(peripheral.clone());
                    map.peripherals.push(peripheral);
                }
            }
            Err(reason) => map.skipped.push(Skipped { name, reason }),
        }
    }
    Ok(map)
}

/// One `<peripheral>` element resolved: its own words over the ones it
/// derives from, its `dim` expanded, its registers flattened.
fn peripheral(
    element: &xml::Xml,
    width: u32,
    resolved: &[Peripheral],
    notes: &mut Vec<String>,
) -> Result<Vec<Peripheral>, String> {
    let name = element
        .child("name")
        .map(xml::Xml::text)
        .filter(|name| !name.is_empty())
        .ok_or("no <name>")?;
    let derived = element.attr("derivedFrom").map(str::to_string);
    let base: Option<Peripheral> = match &derived {
        Some(from) => Some(
            resolved
                .iter()
                .find(|p| &p.name == from)
                .ok_or_else(|| format!("derives from {from}, which the file does not name"))?
                .clone(),
        ),
        None => None,
    };
    let description = element
        .child("description")
        .map(xml::Xml::text)
        .filter(|text| !text.is_empty())
        .or_else(|| base.as_ref().map(|b| b.description.clone()))
        .unwrap_or_default();
    let group = element
        .child("groupName")
        .map(xml::Xml::text)
        .filter(|text| !text.is_empty())
        .or_else(|| base.as_ref().map(|b| b.group.clone()))
        .unwrap_or_default();
    let address = match element.child("baseAddress").map(xml::Xml::text) {
        Some(text) => Some(number(&text).map_err(|why| format!("<baseAddress>: {why}"))?),
        None => base.as_ref().map(|b| b.base),
    };
    let base_address = address.ok_or("no <baseAddress>")?;
    let mut blocks: Vec<AddressBlock> = element
        .children("addressBlock")
        .filter_map(|block| {
            let size = block.child("size").map(xml::Xml::text)?;
            let size = number(&size).ok()?;
            let offset = block
                .child("offset")
                .map(xml::Xml::text)
                .and_then(|text| number(&text).ok())
                .unwrap_or(0);
            let usage = block
                .child("usage")
                .map(xml::Xml::text)
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| "registers".into());
            Some(AddressBlock {
                offset,
                size,
                usage,
            })
        })
        .collect();
    if blocks.is_empty() {
        if let Some(from) = &base {
            blocks = from.blocks.clone();
        }
    }
    let mut interrupts: Vec<Interrupt> = element
        .children("interrupt")
        .filter_map(|interrupt| {
            let value = interrupt.child("value").map(xml::Xml::text)?;
            let value = number(&value).ok()?;
            let name = interrupt
                .child("name")
                .map(xml::Xml::text)
                .unwrap_or_default();
            Some(Interrupt { name, value })
        })
        .collect();
    if interrupts.is_empty() {
        if let Some(from) = &base {
            interrupts = from.interrupts.clone();
        }
    }
    // The registers: the inherited ones, with the peripheral's own
    // replacing them by name and adding the rest.
    let mut registers = base
        .as_ref()
        .map(|b| b.registers.clone())
        .unwrap_or_default();
    if let Some(own) = element.child("registers") {
        let raws = raw_registers(own);
        let mut flattened = Vec::new();
        let mut ctx = Context {
            width,
            peripheral: &name,
            notes: &mut *notes,
        };
        flatten(&raws, "", "", 0, &mut ctx, &mut flattened);
        for register in flattened {
            match registers.iter_mut().find(|held| held.name == register.name) {
                Some(held) => *held = register,
                None => registers.push(register),
            }
        }
    }
    sort_registers(&mut registers, &name, notes);
    let dim = dim_of(element)?;
    let mut made = Vec::new();
    match dim {
        Some(dim) => {
            if !name.contains("%s") {
                return Err(format!("dim of {} without %s in its name", dim.count));
            }
            for index in &dim.indices {
                let mut instance = Peripheral {
                    name: name.replace("%s", index),
                    description: description.clone(),
                    group: group.clone(),
                    base: base_address + dim.increment * made.len() as u64,
                    blocks: blocks.clone(),
                    interrupts: interrupts.clone(),
                    registers: registers.clone(),
                    derived_from: derived.clone(),
                };
                if instance.blocks.is_empty() {
                    let size = struct_size(&instance);
                    if size > 0 {
                        instance.blocks.push(AddressBlock {
                            offset: 0,
                            size,
                            usage: "registers".into(),
                        });
                    }
                }
                made.push(instance);
            }
        }
        None => {
            let mut peripheral = Peripheral {
                name,
                description,
                group,
                base: base_address,
                blocks,
                interrupts,
                registers,
                derived_from: derived,
            };
            if peripheral.blocks.is_empty() {
                let size = struct_size(&peripheral);
                if size > 0 {
                    peripheral.blocks.push(AddressBlock {
                        offset: 0,
                        size,
                        usage: "registers".into(),
                    });
                }
            }
            made.push(peripheral);
        }
    }
    Ok(made)
}

/// Sort the registers by offset and drop the ones that overlap another or
/// that C cannot hold: a width that is no integer of bytes, an offset the
/// width does not align to.
fn sort_registers(registers: &mut Vec<Register>, peripheral: &str, notes: &mut Vec<String>) {
    registers.sort_by_key(|r| (r.offset, r.name.clone()));
    let mut kept: Vec<Register> = Vec::new();
    for register in registers.drain(..) {
        let bytes = u64::from(register.width) / 8;
        if !matches!(register.width, 8 | 16 | 32 | 64) {
            notes.push(format!(
                "{peripheral}: {} is {} bits wide, which C does not hold: left out",
                register.display, register.width
            ));
            continue;
        }
        if register.offset % bytes != 0 {
            notes.push(format!(
                "{peripheral}: {} at {:#x} is not aligned to its {} bytes: left out",
                register.display, register.offset, bytes
            ));
            continue;
        }
        if let Some(last) = kept.last() {
            if register.offset < last.offset + last.span() {
                notes.push(format!(
                    "{peripheral}: {} at {:#x} overlaps {}: left out",
                    register.display, register.offset, last.display
                ));
                continue;
            }
        }
        kept.push(register);
    }
    *registers = kept;
}

/// A register or cluster as the file declares it, before inheritance and
/// flattening.
#[derive(Debug, Clone)]
struct RawRegister {
    name: String,
    description: String,
    offset: Option<u64>,
    width: Option<u32>,
    access: Option<String>,
    reset: Option<u64>,
    fields: Vec<Field>,
    derived: Option<String>,
    dim: Option<Dim>,
    /// Why the `dim` did not read, when it did not.
    dim_error: Option<String>,
    /// The children of a cluster; empty for a register.
    children: Vec<RawRegister>,
    cluster: bool,
}

/// Read the `<register>` and `<cluster>` children of a `<registers>`
/// element, in order.
fn raw_registers(element: &xml::Xml) -> Vec<RawRegister> {
    element
        .children
        .iter()
        .filter(|child| child.name == "register" || child.name == "cluster")
        .map(raw_register)
        .collect()
}

/// One `<register>` or `<cluster>` element as it stands.
fn raw_register(element: &xml::Xml) -> RawRegister {
    let cluster = element.name == "cluster";
    let text = |name: &str| {
        element
            .child(name)
            .map(xml::Xml::text)
            .filter(|text| !text.is_empty())
    };
    let fields = element
        .child("fields")
        .map(|fields| {
            let elements: Vec<&xml::Xml> = fields.children("field").collect();
            // The value lists that go by a name, across all the fields:
            // an enumeratedValues that derives from one takes its values.
            let named: Vec<(String, Vec<EnumValue>)> = elements
                .iter()
                .flat_map(|field| field.children("enumeratedValues"))
                .filter(|values| values.attr("derivedFrom").is_none())
                .filter_map(|values| {
                    let name = values.child("name").map(xml::Xml::text)?;
                    Some((name, enum_values(values)))
                })
                .collect();
            elements.iter().map(|el| field(el, &named)).collect()
        })
        .unwrap_or_default();
    let (dim, dim_error) = match dim_of(element) {
        Ok(dim) => (dim, None),
        Err(reason) => (None, Some(reason)),
    };
    RawRegister {
        name: text("name").unwrap_or_default(),
        description: text("description").unwrap_or_default(),
        offset: text("addressOffset").and_then(|text| number(&text).ok()),
        width: text("size").and_then(|text| text.parse().ok()),
        access: text("access"),
        reset: text("resetValue").and_then(|text| number(&text).ok()),
        fields,
        derived: element.attr("derivedFrom").map(str::to_string),
        dim,
        dim_error,
        children: if cluster {
            element
                .child("registers")
                .map(raw_registers)
                .unwrap_or_default()
        } else {
            Vec::new()
        },
        cluster,
    }
}

/// The values one `<enumeratedValues>` element declares.
fn enum_values(element: &xml::Xml) -> Vec<EnumValue> {
    element
        .children("enumeratedValue")
        .filter_map(|value| {
            let name = value.child("name").map(xml::Xml::text)?;
            let spelled = value.child("value").map(xml::Xml::text)?;
            let parsed = number(&spelled).ok()?;
            let description = value
                .child("description")
                .map(xml::Xml::text)
                .unwrap_or_default();
            Some(EnumValue {
                name,
                value: parsed,
                description,
            })
        })
        .collect()
}

/// One `<field>` element: its bits by whichever of the three spellings the
/// file uses, and its enumerated values — a list that derives from another
/// takes the values of the list the name points at.
fn field(element: &xml::Xml, named: &[(String, Vec<EnumValue>)]) -> Field {
    let text = |name: &str| {
        element
            .child(name)
            .map(xml::Xml::text)
            .filter(|text| !text.is_empty())
    };
    let mut bits: Option<(u32, u32)> = None;
    if let (Some(lsb), Some(msb)) = (text("lsb"), text("msb")) {
        if let (Ok(lsb), Ok(msb)) = (lsb.parse(), msb.parse()) {
            bits = Some((lsb, msb));
        }
    }
    if bits.is_none() {
        if let (Some(offset), Some(width)) = (text("bitOffset"), text("bitWidth")) {
            if let (Ok(offset), Ok(width)) = (offset.parse::<u32>(), width.parse::<u32>()) {
                if width > 0 {
                    bits = Some((offset, offset + width - 1));
                }
            }
        }
    }
    if bits.is_none() {
        if let Some(range) = text("bitRange") {
            // `[msb:lsb]`
            let inner = range.trim_start_matches('[').trim_end_matches(']');
            if let Some((msb, lsb)) = inner.split_once(':') {
                if let (Ok(msb), Ok(lsb)) = (msb.trim().parse(), lsb.trim().parse()) {
                    bits = Some((lsb, msb));
                }
            }
        }
    }
    let (lsb, msb) = bits.unwrap_or((0, 0));
    let values = element
        .children("enumeratedValues")
        .flat_map(|values| match values.attr("derivedFrom") {
            Some(from) => named
                .iter()
                .find(|(name, _)| name == from)
                .map(|(_, values)| values.clone())
                .unwrap_or_default(),
            None => enum_values(values),
        })
        .collect();
    Field {
        name: text("name").unwrap_or_default(),
        description: text("description").unwrap_or_default(),
        lsb,
        msb,
        values,
    }
}

/// A `dim` declaration: how many instances, the bytes between them, and
/// the index each takes — `dimIndex` when the file gives one, the numbers
/// from 0 otherwise.
#[derive(Debug, Clone)]
struct Dim {
    count: u32,
    increment: u64,
    indices: Vec<String>,
}

/// Read the `dim`, `dimIncrement` and `dimIndex` of an element, when it
/// declares a `dim`.
fn dim_of(element: &xml::Xml) -> Result<Option<Dim>, String> {
    let Some(count) = element.child("dim").map(xml::Xml::text) else {
        return Ok(None);
    };
    let count: u32 = count
        .parse()
        .map_err(|_| format!("<dim> {count:?} is not a count"))?;
    if count == 0 {
        return Err("<dim> is 0".into());
    }
    let increment = element
        .child("dimIncrement")
        .map(xml::Xml::text)
        .ok_or("<dim> without <dimIncrement>")?;
    let increment = number(&increment).map_err(|why| format!("<dimIncrement>: {why}"))?;
    let indices = match element.child("dimIndex").map(xml::Xml::text) {
        Some(text) => {
            let made = dim_indices(&text, count);
            match made {
                Some(indices) if indices.len() == count as usize => indices,
                _ => return Err(format!("<dimIndex> {text:?} does not name {count} indices")),
            }
        }
        None => (0..count).map(|index| index.to_string()).collect(),
    };
    Ok(Some(Dim {
        count,
        increment,
        indices,
    }))
}

/// The indices a `dimIndex` spells: a comma list (`A,B,C`, `0,2,4`) or a
/// range (`0-5`); `None` when it does not read.
fn dim_indices(text: &str, count: u32) -> Option<Vec<String>> {
    if let Some((from, to)) = text.split_once('-') {
        let from = number(from.trim()).ok()?;
        let to = number(to.trim()).ok()?;
        if to < from || to - from + 1 != u64::from(count) {
            return None;
        }
        return Some((from..=to).map(|index| index.to_string()).collect());
    }
    let parts: Vec<String> = text
        .split(',')
        .map(|part| part.trim().to_string())
        .collect();
    if parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    Some(parts)
}

/// What the flattening of one peripheral's registers walks with: the
/// device's register width, the peripheral's name for the notes, and the
/// notes left on the way.
struct Context<'a> {
    width: u32,
    peripheral: &'a str,
    notes: &'a mut Vec<String>,
}

/// Flatten the raw registers and clusters into the peripheral's members:
/// clusters prefixed onto their children's names, arrays expanded, names
/// mended to C identifiers and made unique. `prefix` builds the C member
/// names with underscores; `display` builds the name the comment calls the
/// register, the cluster path as dots.
fn flatten(
    raws: &[RawRegister],
    prefix: &str,
    display: &str,
    base: u64,
    ctx: &mut Context,
    out: &mut Vec<Register>,
) {
    let width = ctx.width;
    let peripheral = ctx.peripheral;
    // Inheritance first: a register or cluster that derives from an
    // earlier one takes its words, its own over them.
    let mut resolved: Vec<RawRegister> = Vec::new();
    for raw in raws {
        let mut raw = raw.clone();
        if let Some(from) = &raw.derived {
            // A reference may carry the cluster path it sits in; the
            // search is relative to this scope, so the path comes off.
            let local = from.strip_prefix(display).unwrap_or(from);
            if let Some(base) = find_raw(&resolved, local).or_else(|| find_raw(&resolved, from)) {
                if raw.description.is_empty() {
                    raw.description = base.description.clone();
                }
                if raw.width.is_none() {
                    raw.width = base.width;
                }
                if raw.access.is_none() {
                    raw.access = base.access.clone();
                }
                if raw.reset.is_none() {
                    raw.reset = base.reset;
                }
                if raw.fields.is_empty() {
                    raw.fields = base.fields.clone();
                }
                if raw.children.is_empty() {
                    raw.children = base.children.clone();
                }
            } else {
                ctx.notes.push(format!(
                    "{peripheral}: {} derives from {from}, which is not declared before it: left out",
                    raw.name
                ));
                continue;
            }
        }
        resolved.push(raw);
    }
    let mut used: BTreeSet<String> = out.iter().map(|r| r.name.clone()).collect();
    for raw in &resolved {
        if raw.name.is_empty() {
            ctx.notes
                .push(format!("{peripheral}: a register with no name: left out"));
            continue;
        }
        let Some(offset) = raw.offset else {
            ctx.notes.push(format!(
                "{peripheral}: {} has no <addressOffset>: left out",
                raw.name
            ));
            continue;
        };
        let offset = base + offset;
        if let Some(reason) = &raw.dim_error {
            ctx.notes
                .push(format!("{peripheral}: {}: {reason}: left out", raw.name));
            continue;
        }
        let dim = raw.dim.clone();
        if raw.cluster {
            let short = strip_dim(&raw.name);
            match dim {
                Some(dim) => {
                    for (index, label) in dim.indices.iter().enumerate() {
                        let prefix = format!("{prefix}{short}_{label}_");
                        let display = format!("{display}{short}_{label}.");
                        flatten(
                            &raw.children,
                            &prefix,
                            &display,
                            offset + dim.increment * index as u64,
                            ctx,
                            out,
                        );
                    }
                }
                None => {
                    let prefix = format!("{prefix}{short}_");
                    let display = format!("{display}{short}.");
                    flatten(&raw.children, &prefix, &display, offset, ctx, out);
                }
            }
            continue;
        }
        let reg_width = raw.width.unwrap_or(width);
        let access = raw
            .access
            .clone()
            .unwrap_or_else(|| "read-write".to_string());
        let display = format!("{display}{}", raw.name);
        match dim {
            Some(dim) if dim.increment == u64::from(reg_width) / 8 && reg_width % 8 == 0 => {
                let short = strip_dim(&raw.name);
                let name = unique(
                    &mut used,
                    mended(&short, &format!("{prefix}{short}"), peripheral, ctx.notes),
                );
                out.push(Register {
                    name,
                    display,
                    description: raw.description.clone(),
                    offset,
                    width: reg_width,
                    access,
                    reset: raw.reset,
                    fields: raw.fields.clone(),
                    count: dim.count,
                    stride: dim.increment,
                });
            }
            Some(dim) => {
                for (index, label) in dim.indices.iter().enumerate() {
                    let name = unique(
                        &mut used,
                        mended(
                            &format!("{}_{}", strip_dim(&raw.name), label),
                            &format!("{prefix}{}_{}", strip_dim(&raw.name), label),
                            peripheral,
                            ctx.notes,
                        ),
                    );
                    out.push(Register {
                        name,
                        display: format!("{display}_{label}"),
                        description: raw.description.clone(),
                        offset: offset + dim.increment * index as u64,
                        width: reg_width,
                        access: access.clone(),
                        reset: raw.reset,
                        fields: raw.fields.clone(),
                        count: 1,
                        stride: u64::from(reg_width) / 8,
                    });
                }
            }
            None => {
                let name = unique(
                    &mut used,
                    mended(
                        &raw.name,
                        &format!("{prefix}{}", raw.name),
                        peripheral,
                        ctx.notes,
                    ),
                );
                out.push(Register {
                    name,
                    display,
                    description: raw.description.clone(),
                    offset,
                    width: reg_width,
                    access,
                    reset: raw.reset,
                    fields: raw.fields.clone(),
                    count: 1,
                    stride: u64::from(reg_width) / 8,
                });
            }
        }
    }
}

/// Find an earlier raw register or cluster by name — bare or by its
/// cluster path (`TIMER.CTRL`) — clusters searched too.
fn find_raw<'a>(raws: &'a [RawRegister], name: &str) -> Option<&'a RawRegister> {
    for raw in raws {
        if raw.name == name {
            return Some(raw);
        }
        if raw.cluster {
            if let Some(found) = find_raw_path(&raw.children, &raw.name, name) {
                return Some(found);
            }
        }
    }
    None
}

/// The same search under a cluster path.
fn find_raw_path<'a>(raws: &'a [RawRegister], prefix: &str, name: &str) -> Option<&'a RawRegister> {
    for raw in raws {
        let path = format!("{prefix}.{}", raw.name);
        if raw.name == name || path == name {
            return Some(raw);
        }
        if raw.cluster {
            if let Some(found) = find_raw_path(&raw.children, &path, name) {
                return Some(found);
            }
        }
    }
    None
}

/// A name with its `[%s]` or `%s` dim placeholder taken out.
fn strip_dim(name: &str) -> String {
    name.replace("[%s]", "").replace("%s", "")
}

/// A name mended to a C identifier: what is not a letter, a digit or an
/// underscore becomes one, and a leading digit gains an underscore before
/// it. The full name (with its cluster prefix) is what is mended; a change
/// is noted.
fn mended(name: &str, full: &str, peripheral: &str, notes: &mut Vec<String>) -> String {
    let mut out = String::new();
    for (index, ch) in full.char_indices() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
        if index == 0 && ch.is_ascii_digit() {
            out.insert(0, '_');
        }
    }
    if out != full {
        notes.push(format!(
            "{peripheral}: {name} is read as {out}, a C identifier"
        ));
    }
    out
}

/// A name made unique among the ones used, `_2`, `_3` … past them.
fn unique(used: &mut BTreeSet<String>, name: String) -> String {
    let mut candidate = name.clone();
    let mut suffix = 2;
    while used.contains(&candidate) {
        candidate = format!("{name}_{suffix}");
        suffix += 1;
    }
    used.insert(candidate.clone());
    candidate
}

/// A number as SVD spells it: decimal, hexadecimal with `0x`, or binary
/// with `#`.
fn number(text: &str) -> Result<u64, String> {
    let text = text.trim().trim_start_matches('+');
    let made = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else if let Some(binary) = text.strip_prefix('#') {
        u64::from_str_radix(binary, 2)
    } else {
        text.parse::<u64>()
    };
    made.map_err(|_| format!("{text:?} is not a number"))
}

// ---------------------------------------------------------------------
// The XML subset SVD uses.

mod xml {
    /// One element: its name (a namespace prefix stripped), its attributes,
    /// its child elements and its text.
    #[derive(Debug, Clone)]
    pub(super) struct Xml {
        pub name: String,
        pub attrs: Vec<(String, String)>,
        pub children: Vec<Xml>,
        pub text: String,
    }

    impl Xml {
        /// The first child of the name, when there is one.
        pub fn child(&self, name: &str) -> Option<&Xml> {
            self.children.iter().find(|child| child.name == name)
        }

        /// Every child of the name, in order.
        pub fn children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Xml> {
            self.children.iter().filter(move |child| child.name == name)
        }

        /// The attribute's value, when it is there.
        pub fn attr(&self, name: &str) -> Option<&str> {
            self.attrs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        }

        /// The element's text with its whitespace folded: runs of spaces,
        /// tabs and newlines become one space, and the ends are trimmed.
        pub fn text(&self) -> String {
            self.text.split_whitespace().collect::<Vec<_>>().join(" ")
        }
    }

    /// Read the document's root element. What is not well-formed XML of
    /// the subset — a mismatched or unclosed tag, a stray `<`, an unknown
    /// entity — is refused with its line.
    pub fn parse(text: &str) -> Result<Xml, String> {
        let mut parser = Parser { text, at: 0 };
        parser.misc()?;
        let root = parser.element(0)?;
        parser.misc()?;
        if parser.at != text.len() {
            return Err(parser.error("content after the root element"));
        }
        Ok(root)
    }

    struct Parser<'a> {
        text: &'a str,
        at: usize,
    }

    impl<'a> Parser<'a> {
        fn error(&self, message: &str) -> String {
            let line = self.text[..self.at].matches('\n').count() + 1;
            format!("line {line}: {message}")
        }

        fn rest(&self) -> &'a str {
            &self.text[self.at..]
        }

        fn starts(&self, prefix: &str) -> bool {
            self.rest().starts_with(prefix)
        }

        fn skip(&mut self, count: usize) {
            self.at += count;
        }

        fn whitespace(&mut self) {
            while self.rest().chars().next().is_some_and(char::is_whitespace) {
                self.at += self.rest().chars().next().unwrap().len_utf8();
            }
        }

        /// Skip what may stand before or after the root: whitespace,
        /// comments, processing instructions and the doctype.
        fn misc(&mut self) -> Result<(), String> {
            loop {
                self.whitespace();
                if self.starts("<!--") {
                    self.comment()?;
                } else if self.starts("<?") {
                    self.until("?>", "an unclosed processing instruction")?;
                } else if self.starts("<!") {
                    self.doctype()?;
                } else {
                    return Ok(());
                }
            }
        }

        fn comment(&mut self) -> Result<(), String> {
            self.skip(4);
            self.until("-->", "an unclosed comment")
        }

        /// Skip to just past `end`, refusing with `message` when the text
        /// ends first.
        fn until(&mut self, end: &str, message: &str) -> Result<(), String> {
            match self.rest().find(end) {
                Some(found) => {
                    self.skip(found + end.len());
                    Ok(())
                }
                None => Err(self.error(message)),
            }
        }

        /// Skip a `<!DOCTYPE …>` declaration, an internal subset in
        /// brackets included.
        fn doctype(&mut self) -> Result<(), String> {
            self.skip(2);
            let mut depth = 0usize;
            while let Some(ch) = self.rest().chars().next() {
                self.skip(ch.len_utf8());
                match ch {
                    '[' => depth += 1,
                    ']' => depth = depth.saturating_sub(1),
                    '>' if depth == 0 => return Ok(()),
                    _ => {}
                }
            }
            Err(self.error("an unclosed doctype"))
        }

        /// Read one element, its attributes, its children and its text.
        fn element(&mut self, depth: usize) -> Result<Xml, String> {
            if depth > 64 {
                return Err(self.error("the XML nests too deep"));
            }
            if !self.starts("<") {
                return Err(self.error("expected an element"));
            }
            self.skip(1);
            let name = self.name()?;
            let mut attrs = Vec::new();
            let mut children = Vec::new();
            let mut text = String::new();
            // The attributes, to the tag's end.
            let self_closed = loop {
                self.whitespace();
                if self.starts("/>") {
                    self.skip(2);
                    break true;
                }
                if self.starts(">") {
                    self.skip(1);
                    break false;
                }
                let key = self.name()?;
                self.whitespace();
                if !self.starts("=") {
                    return Err(self.error(&format!("attribute {key} has no value")));
                }
                self.skip(1);
                self.whitespace();
                let quote = self
                    .rest()
                    .chars()
                    .next()
                    .filter(|ch| *ch == '"' || *ch == '\'')
                    .ok_or_else(|| self.error("an attribute value is not quoted"))?;
                self.skip(quote.len_utf8());
                let end = self
                    .rest()
                    .find(quote)
                    .ok_or_else(|| self.error("an unclosed attribute value"))?;
                let value = entities(&self.rest()[..end]).map_err(|why| self.error(&why))?;
                self.skip(end + quote.len_utf8());
                attrs.push((key, value));
            };
            if self_closed {
                return Ok(Xml {
                    name,
                    attrs,
                    children,
                    text,
                });
            }
            // The content, to the closing tag.
            loop {
                if self.starts("</") {
                    self.skip(2);
                    let closing = self.name()?;
                    self.whitespace();
                    if !self.starts(">") {
                        return Err(self.error("an unclosed closing tag"));
                    }
                    self.skip(1);
                    if closing != name {
                        return Err(self.error(&format!("</{closing}> closes <{name}>")));
                    }
                    return Ok(Xml {
                        name,
                        attrs,
                        children,
                        text,
                    });
                }
                if self.starts("<!--") {
                    self.comment()?;
                    continue;
                }
                if self.starts("<![CDATA[") {
                    self.skip(9);
                    let end = self
                        .rest()
                        .find("]]>")
                        .ok_or_else(|| self.error("unclosed CDATA"))?;
                    text.push_str(&self.rest()[..end]);
                    self.skip(end + 3);
                    continue;
                }
                if self.starts("<?") {
                    self.until("?>", "an unclosed processing instruction")?;
                    continue;
                }
                if self.starts("<!") {
                    self.doctype()?;
                    continue;
                }
                if self.starts("<") {
                    children.push(self.element(depth + 1)?);
                    continue;
                }
                if self.at == self.text.len() {
                    return Err(self.error(&format!("<{name}> is never closed")));
                }
                let end = self.rest().find('<').unwrap_or(self.rest().len());
                let chunk = entities(&self.rest()[..end]).map_err(|why| self.error(&why))?;
                text.push_str(&chunk);
                self.skip(end);
            }
        }

        /// Read a name: to the first character that cannot be in one. A
        /// namespace prefix is stripped — `xs:schema` reads as `schema`.
        fn name(&mut self) -> Result<String, String> {
            let end = self
                .rest()
                .find(|ch: char| ch.is_whitespace() || matches!(ch, '/' | '>' | '=' | '<'))
                .unwrap_or(self.rest().len());
            if end == 0 {
                return Err(self.error("expected a name"));
            }
            let name = &self.rest()[..end];
            self.skip(end);
            Ok(name.rsplit(':').next().unwrap_or(name).to_string())
        }
    }

    /// Decode the five entities and the numeric character references; an
    /// entity of another name is refused rather than left as text.
    fn entities(text: &str) -> Result<String, String> {
        if !text.contains('&') {
            return Ok(text.to_string());
        }
        let mut out = String::new();
        let mut rest = text;
        while let Some(found) = rest.find('&') {
            out.push_str(&rest[..found]);
            rest = &rest[found..];
            let end = rest
                .find(';')
                .ok_or("an entity reference has no semicolon")?;
            let name = &rest[1..end];
            let decoded = match name {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                _ => {
                    let code = if let Some(hex) =
                        name.strip_prefix("#x").or_else(|| name.strip_prefix("#X"))
                    {
                        u32::from_str_radix(hex, 16)
                    } else if let Some(decimal) = name.strip_prefix('#') {
                        decimal.parse::<u32>()
                    } else {
                        return Err(format!("unknown entity &{name};"));
                    };
                    let code = code.map_err(|_| format!("&{name}; is not a character"))?;
                    char::from_u32(code).ok_or_else(|| format!("&{name}; is not a character"))?
                }
            };
            out.push(decoded);
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small device: one peripheral with two registers and a field.
    const SMALL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<device schemaVersion="1.1" xmlns:xs="http://www.w3.org/2001/XMLSchema-instance">
  <name>TESTDEV</name>
  <description>A test device</description>
  <width>32</width>
  <peripherals>
    <peripheral>
      <name>GPIOA</name>
      <description>General purpose I/O</description>
      <groupName>GPIO</groupName>
      <baseAddress>0x40010800</baseAddress>
      <addressBlock>
        <offset>0</offset>
        <size>0x400</size>
        <usage>registers</usage>
      </addressBlock>
      <interrupt>
        <name>EXTI0</name>
        <value>6</value>
      </interrupt>
      <registers>
        <register>
          <name>CRL</name>
          <description>Port configuration register low</description>
          <addressOffset>0x0</addressOffset>
          <size>32</size>
          <access>read-write</access>
          <resetValue>0x44444444</resetValue>
          <fields>
            <field>
              <name>MODE0</name>
              <description>Port x mode bits</description>
              <bitOffset>0</bitOffset>
              <bitWidth>2</bitWidth>
              <enumeratedValues>
                <enumeratedValue>
                  <name>INPUT</name>
                  <description>Input mode</description>
                  <value>0</value>
                </enumeratedValue>
                <enumeratedValue>
                  <name>OUTPUT</name>
                  <value>1</value>
                </enumeratedValue>
              </enumeratedValues>
            </field>
          </fields>
        </register>
        <register>
          <name>IDR</name>
          <description>Port input data</description>
          <addressOffset>0x8</addressOffset>
          <access>read-only</access>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
"#;

    #[test]
    fn a_small_device_reads_whole() {
        let map = parse(SMALL).expect("the SVD reads");
        assert_eq!(map.device, "TESTDEV");
        assert_eq!(map.width, 32);
        assert!(map.skipped.is_empty(), "{:?}", map.skipped);
        assert_eq!(map.peripherals.len(), 1);
        let p = &map.peripherals[0];
        assert_eq!(p.name, "GPIOA");
        assert_eq!(p.base, 0x40010800);
        assert_eq!(p.group, "GPIO");
        assert_eq!(p.blocks.len(), 1);
        assert_eq!(p.blocks[0].size, 0x400);
        assert_eq!(p.interrupts.len(), 1);
        assert_eq!(p.interrupts[0].value, 6);
        assert_eq!(p.registers.len(), 2);
        assert_eq!(p.registers[0].name, "CRL");
        assert_eq!(p.registers[0].reset, Some(0x44444444));
        assert_eq!(p.registers[1].name, "IDR");
        assert_eq!(p.registers[1].offset, 8);
        assert_eq!(p.registers[1].width, 32, "the device width is the default");
        let field = &p.registers[0].fields[0];
        assert_eq!(field.name, "MODE0");
        assert_eq!((field.lsb, field.msb), (0, 1));
        assert_eq!(field.values.len(), 2);
        assert_eq!(field.values[0].name, "INPUT");
        assert_eq!(field.values[0].description, "Input mode");
    }

    #[test]
    fn the_structure_holds_the_registers_with_the_gaps_reserved() {
        let map = parse(SMALL).expect("the SVD reads");
        let p = &map.peripherals[0];
        let c = struct_c(p);
        assert!(c.starts_with("struct GPIOA {\n"), "{c}");
        assert!(c.contains("  uint32_t CRL; /* 0x0 */\n"), "{c}");
        assert!(
            c.contains("  uint8_t reserved_4[4]; /* 0x4: 4 bytes reserved */\n"),
            "{c}"
        );
        assert!(c.contains("  uint32_t IDR; /* 0x8 */\n"), "{c}");
        // The block reaches past the registers: the struct is padded to it.
        assert!(c.contains("uint8_t reserved_c[1012];"), "{c}");
        assert!(c.ends_with("};"), "{c}");
        assert_eq!(struct_size(p), 0x400);
        assert_eq!(struct_name(p), "struct GPIOA");
    }

    #[test]
    fn the_comments_name_the_place_and_what_it_holds() {
        let map = parse(SMALL).expect("the SVD reads");
        let p = &map.peripherals[0];
        let comment = peripheral_comment(p);
        assert!(
            comment.starts_with("GPIOA: General purpose I/O (group GPIO)"),
            "{comment}"
        );
        assert!(
            comment.contains("registers 0x40010800-0x40010c00"),
            "{comment}"
        );
        assert!(comment.contains("interrupt 6 (EXTI0)"), "{comment}");
        let comment = register_comment(p, &p.registers[0]);
        assert!(
            comment.starts_with(
                "GPIOA.CRL: Port configuration register low (read-write, reset 0x44444444)"
            ),
            "{comment}"
        );
        assert!(
            comment.contains("MODE0[1:0]: Port x mode bits: INPUT=0 (Input mode), OUTPUT=1"),
            "{comment}"
        );
    }

    #[test]
    fn the_segments_map_the_address_blocks() {
        let map = parse(SMALL).expect("the SVD reads");
        let segments = segments(&map.peripherals[0]);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].name, "GPIOA");
        assert_eq!(segments[0].address, 0x40010800);
        assert_eq!(segments[0].size, 0x400);
    }

    #[test]
    fn a_derived_peripheral_inherits_and_overrides() {
        let text = SMALL.replace(
            "</peripherals>",
            r#"    <peripheral derivedFrom="GPIOA">
      <name>GPIOB</name>
      <baseAddress>0x40010C00</baseAddress>
      <interrupt>
        <name>EXTI1</name>
        <value>7</value>
      </interrupt>
    </peripheral>
  </peripherals>"#,
        );
        let map = parse(&text).expect("the SVD reads");
        assert_eq!(map.peripherals.len(), 2);
        let b = &map.peripherals[1];
        assert_eq!(b.name, "GPIOB");
        assert_eq!(b.base, 0x40010c00);
        assert_eq!(b.derived_from.as_deref(), Some("GPIOA"));
        assert_eq!(b.registers.len(), 2, "the registers are inherited");
        assert_eq!(b.description, "General purpose I/O");
        assert_eq!(b.interrupts.len(), 1);
        assert_eq!(b.interrupts[0].value, 7, "its own interrupt replaces");
        assert_eq!(b.blocks[0].size, 0x400);
    }

    #[test]
    fn a_derived_register_takes_the_fields_of_its_base() {
        let text = SMALL.replace(
            "</registers>",
            r#"        <register derivedFrom="CRL">
          <name>CRH</name>
          <addressOffset>0x4</addressOffset>
        </register>
      </registers>"#,
        );
        let map = parse(&text).expect("the SVD reads");
        let p = &map.peripherals[0];
        assert_eq!(p.registers.len(), 3);
        let crh = p.registers.iter().find(|r| r.name == "CRH").expect("CRH");
        assert_eq!(crh.offset, 4);
        assert_eq!(crh.fields.len(), 1, "the fields are inherited");
        assert_eq!(crh.reset, Some(0x44444444));
        // The gap at 0x4 is filled now: no reserved bytes between CRL and CRH.
        let c = struct_c(p);
        assert!(!c.contains("reserved_4"), "{c}");
    }

    #[test]
    fn a_cluster_flattens_its_registers_under_its_name() {
        let text = SMALL.replace(
            "</registers>",
            r#"        <cluster>
          <name>TIMER</name>
          <addressOffset>0x20</addressOffset>
          <registers>
            <register>
              <name>CTRL</name>
              <addressOffset>0x0</addressOffset>
            </register>
            <register>
              <name>STAT</name>
              <addressOffset>0x4</addressOffset>
            </register>
          </registers>
        </cluster>
      </registers>"#,
        );
        let map = parse(&text).expect("the SVD reads");
        let p = &map.peripherals[0];
        let ctrl = p
            .registers
            .iter()
            .find(|r| r.name == "TIMER_CTRL")
            .expect("TIMER_CTRL");
        assert_eq!(ctrl.offset, 0x20);
        assert_eq!(ctrl.display, "TIMER.CTRL");
        let stat = p
            .registers
            .iter()
            .find(|r| r.name == "TIMER_STAT")
            .expect("TIMER_STAT");
        assert_eq!(stat.offset, 0x24);
        let comment = register_comment(p, ctrl);
        assert!(comment.starts_with("GPIOA.TIMER.CTRL"), "{comment}");
    }

    #[test]
    fn a_packed_register_array_is_one_c_array() {
        let text = SMALL.replace(
            "</registers>",
            r#"        <register>
          <name>DATA[%s]</name>
          <addressOffset>0x40</addressOffset>
          <dim>4</dim>
          <dimIncrement>4</dimIncrement>
        </register>
      </registers>"#,
        );
        let map = parse(&text).expect("the SVD reads");
        let p = &map.peripherals[0];
        let data = p.registers.iter().find(|r| r.name == "DATA").expect("DATA");
        assert_eq!(data.count, 4);
        assert_eq!(data.offset, 0x40);
        let c = struct_c(p);
        assert!(c.contains("  uint32_t DATA[4]; /* 0x40 */\n"), "{c}");
        let comment = register_comment(p, data);
        assert!(comment.contains("4 registers"), "{comment}");
    }

    #[test]
    fn a_strided_register_array_expands_to_named_members() {
        let text = SMALL.replace(
            "</registers>",
            r#"        <register>
          <name>CH%s</name>
          <addressOffset>0x40</addressOffset>
          <dim>2</dim>
          <dimIncrement>8</dimIncrement>
          <dimIndex>A,B</dimIndex>
        </register>
      </registers>"#,
        );
        let map = parse(&text).expect("the SVD reads");
        let p = &map.peripherals[0];
        let a = p.registers.iter().find(|r| r.name == "CH_A").expect("CH_A");
        let b = p.registers.iter().find(|r| r.name == "CH_B").expect("CH_B");
        assert_eq!(a.offset, 0x40);
        assert_eq!(b.offset, 0x48);
        let c = struct_c(p);
        assert!(c.contains("uint32_t CH_A; /* 0x40 */"), "{c}");
        assert!(c.contains("uint8_t reserved_44[4];"), "{c}");
        assert!(c.contains("uint32_t CH_B; /* 0x48 */"), "{c}");
    }

    #[test]
    fn a_peripheral_array_expands_by_its_indices() {
        let text = SMALL
            .replace("<name>GPIOA</name>", "<name>GPIO%s</name>")
            .replace(
                "<baseAddress>0x40010800</baseAddress>",
                "<baseAddress>0x40010800</baseAddress>\n      <dim>3</dim>\n      <dimIncrement>0x400</dimIncrement>\n      <dimIndex>A,B,C</dimIndex>",
            );
        let map = parse(&text).expect("the SVD reads");
        let names: Vec<&str> = map.peripherals.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["GPIOA", "GPIOB", "GPIOC"]);
        assert_eq!(map.peripherals[1].base, 0x40010c00);
        assert_eq!(map.peripherals[2].base, 0x40011000);
    }

    #[test]
    fn the_field_bits_read_by_all_three_spellings() {
        let text = SMALL.replace(
            "<bitOffset>0</bitOffset>\n              <bitWidth>2</bitWidth>",
            "<bitRange>[3:2]</bitRange>",
        );
        let map = parse(&text).expect("the SVD reads");
        let field = &map.peripherals[0].registers[0].fields[0];
        assert_eq!((field.lsb, field.msb), (2, 3));
        let text = SMALL.replace(
            "<bitOffset>0</bitOffset>\n              <bitWidth>2</bitWidth>",
            "<lsb>4</lsb>\n              <msb>7</msb>",
        );
        let map = parse(&text).expect("the SVD reads");
        let field = &map.peripherals[0].registers[0].fields[0];
        assert_eq!((field.lsb, field.msb), (4, 7));
    }

    #[test]
    fn a_peripheral_with_no_base_address_is_held_back() {
        let text = SMALL.replace("<baseAddress>0x40010800</baseAddress>", "");
        let map = parse(&text).expect("the file reads");
        assert!(map.peripherals.is_empty());
        assert_eq!(map.skipped.len(), 1);
        assert_eq!(map.skipped[0].name, "GPIOA");
        assert!(
            map.skipped[0].reason.contains("baseAddress"),
            "{:?}",
            map.skipped
        );
    }

    #[test]
    fn a_derivation_from_nothing_is_held_back() {
        let text = SMALL.replace("<peripheral>", r#"<peripheral derivedFrom="NOWHERE">"#);
        let map = parse(&text).expect("the file reads");
        assert!(map.peripherals.is_empty());
        assert!(
            map.skipped[0].reason.contains("NOWHERE"),
            "{:?}",
            map.skipped
        );
    }

    #[test]
    fn overlapping_registers_leave_the_later_one_out() {
        let text = SMALL.replace(
            "<addressOffset>0x8</addressOffset>",
            "<addressOffset>0x0</addressOffset>",
        );
        let map = parse(&text).expect("the file reads");
        let p = &map.peripherals[0];
        assert_eq!(p.registers.len(), 1);
        assert!(
            map.notes.iter().any(|n| n.contains("overlaps")),
            "{:?}",
            map.notes
        );
    }

    #[test]
    fn a_misaligned_register_is_left_out_with_a_note() {
        let text = SMALL.replace(
            "<addressOffset>0x8</addressOffset>",
            "<addressOffset>0x2</addressOffset>",
        );
        let map = parse(&text).expect("the file reads");
        let p = &map.peripherals[0];
        assert_eq!(p.registers.len(), 1);
        assert!(
            map.notes.iter().any(|n| n.contains("not aligned")),
            "{:?}",
            map.notes
        );
    }

    #[test]
    fn an_enumerated_values_list_derives_from_the_named_one() {
        let text = SMALL
            .replace(
                "</fields>",
                r#"            <field>
              <name>MODE1</name>
              <bitOffset>2</bitOffset>
              <bitWidth>2</bitWidth>
              <enumeratedValues derivedFrom="MODES"/>
            </field>
          </fields>"#,
            )
            .replace(
                "<enumeratedValues>",
                "<enumeratedValues>\n                <name>MODES</name>",
            );
        let map = parse(&text).expect("the file reads");
        let fields = &map.peripherals[0].registers[0].fields;
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1].name, "MODE1");
        assert_eq!(fields[1].values.len(), 2, "the values are inherited");
        assert_eq!(fields[1].values[0].name, "INPUT");
    }

    #[test]
    fn a_cluster_array_expands_with_its_indices() {
        let text = SMALL.replace(
            "</registers>",
            r#"        <cluster>
          <dim>2</dim>
          <dimIncrement>0x10</dimIncrement>
          <name>CH[%s]</name>
          <addressOffset>0x30</addressOffset>
          <registers>
            <register>
              <name>CTRL</name>
              <addressOffset>0x0</addressOffset>
            </register>
          </registers>
        </cluster>
      </registers>"#,
        );
        let map = parse(&text).expect("the file reads");
        let p = &map.peripherals[0];
        let first = p
            .registers
            .iter()
            .find(|r| r.name == "CH_0_CTRL")
            .expect("CH_0_CTRL");
        let second = p
            .registers
            .iter()
            .find(|r| r.name == "CH_1_CTRL")
            .expect("CH_1_CTRL");
        assert_eq!(first.offset, 0x30);
        assert_eq!(second.offset, 0x40);
        assert_eq!(first.display, "CH_0.CTRL");
    }

    #[test]
    fn a_register_derives_by_its_cluster_path() {
        let text = SMALL.replace(
            "</registers>",
            r#"        <cluster>
          <name>PAIR</name>
          <addressOffset>0x30</addressOffset>
          <registers>
            <register>
              <name>LOW</name>
              <addressOffset>0x0</addressOffset>
              <access>read-only</access>
            </register>
            <register derivedFrom="PAIR.LOW">
              <name>HIGH</name>
              <addressOffset>0x4</addressOffset>
            </register>
          </registers>
        </cluster>
      </registers>"#,
        );
        let map = parse(&text).expect("the file reads");
        let p = &map.peripherals[0];
        let high = p
            .registers
            .iter()
            .find(|r| r.name == "PAIR_HIGH")
            .expect("PAIR_HIGH");
        assert_eq!(high.access, "read-only", "the access is inherited");
    }

    #[test]
    fn a_width_c_does_not_hold_is_left_out_with_a_note() {
        let text = SMALL.replace("<size>32</size>", "<size>24</size>");
        let map = parse(&text).expect("the file reads");
        let p = &map.peripherals[0];
        assert_eq!(p.registers.len(), 1);
        assert_eq!(p.registers[0].name, "IDR");
        assert!(
            map.notes.iter().any(|n| n.contains("24 bits")),
            "{:?}",
            map.notes
        );
    }

    #[test]
    fn a_file_with_no_block_gets_one_covering_its_registers() {
        let text = SMALL.replace(
            r#"      <addressBlock>
        <offset>0</offset>
        <size>0x400</size>
        <usage>registers</usage>
      </addressBlock>
"#,
            "",
        );
        let map = parse(&text).expect("the file reads");
        let p = &map.peripherals[0];
        assert_eq!(p.blocks.len(), 1);
        assert_eq!(p.blocks[0].size, 0xc, "to the last register's end");
        let segments = segments(p);
        assert_eq!(segments[0].size, 0xc);
    }

    #[test]
    fn several_blocks_map_several_segments() {
        let text = SMALL.replace(
            "</addressBlock>",
            r#"      </addressBlock>
      <addressBlock>
        <offset>0x800</offset>
        <size>0x100</size>
        <usage>ram</usage>
      </addressBlock>"#,
        );
        let map = parse(&text).expect("the file reads");
        let segments = segments(&map.peripherals[0]);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].name, "GPIOA");
        assert_eq!(segments[1].name, "GPIOA_1");
        assert_eq!(segments[1].address, 0x40011000);
        assert_eq!(segments[1].size, 0x100);
    }

    #[test]
    fn numbers_read_as_svd_spells_them() {
        assert_eq!(number("0x40010800"), Ok(0x40010800));
        assert_eq!(number("32"), Ok(32));
        assert_eq!(number("#1010"), Ok(10));
        assert_eq!(number("+0x10"), Ok(16));
        assert!(number("zz").is_err());
    }

    #[test]
    fn a_name_that_is_no_c_identifier_is_mended() {
        let text = SMALL.replace("<name>CRL</name>", "<name>CR-L</name>");
        let map = parse(&text).expect("the file reads");
        let p = &map.peripherals[0];
        assert_eq!(p.registers[0].name, "CR_L");
        assert!(
            map.notes.iter().any(|n| n.contains("C identifier")),
            "{:?}",
            map.notes
        );
    }

    #[test]
    fn what_is_not_svd_is_refused() {
        assert!(parse("not xml at all").is_err());
        assert!(parse("<html><body/></html>")
            .unwrap_err()
            .contains("not an SVD file"));
        assert!(parse("<device><name>X</name></device>")
            .unwrap_err()
            .contains("peripherals"));
        let unclosed = SMALL.replace("</device>", "");
        assert!(parse(&unclosed).is_err());
        let mismatched = SMALL.replace("</peripheral>", "</wrong>");
        assert!(parse(&mismatched).is_err());
    }

    #[test]
    fn the_xml_reader_reads_the_subset() {
        let root = xml::parse(
            r#"<?xml version="1.0"?><!-- a comment --><!DOCTYPE device><root a="1" b='two &amp; three'><child>text &lt;here&gt; &#65;&#x42;</child><![CDATA[raw <text>]]></root>"#,
        )
        .expect("the XML reads");
        assert_eq!(root.name, "root");
        assert_eq!(root.attr("a"), Some("1"));
        assert_eq!(root.attr("b"), Some("two & three"));
        assert_eq!(root.child("child").unwrap().text(), "text <here> AB");
        assert!(root.text.contains("raw <text>"));
        assert!(xml::parse("<a><b></a></b>").is_err());
        assert!(xml::parse("<a>").is_err());
        assert!(xml::parse("<a>&nope;</a>").is_err());
        assert!(xml::parse("<a/><b/>").is_err());
    }

    #[test]
    fn a_description_with_whitespace_folds_to_one_line() {
        let text = SMALL.replace(
            "<description>General purpose I/O</description>",
            "<description>General\n   purpose\tI/O</description>",
        );
        let map = parse(&text).expect("the file reads");
        assert_eq!(map.peripherals[0].description, "General purpose I/O");
    }

    #[test]
    fn an_empty_peripheral_still_maps_its_block() {
        let text = SMALL.replace(
            r#"      <registers>
        <register>
          <name>CRL</name>
          <description>Port configuration register low</description>
          <addressOffset>0x0</addressOffset>
          <size>32</size>
          <access>read-write</access>
          <resetValue>0x44444444</resetValue>
          <fields>
            <field>
              <name>MODE0</name>
              <description>Port x mode bits</description>
              <bitOffset>0</bitOffset>
              <bitWidth>2</bitWidth>
              <enumeratedValues>
                <enumeratedValue>
                  <name>INPUT</name>
                  <description>Input mode</description>
                  <value>0</value>
                </enumeratedValue>
                <enumeratedValue>
                  <name>OUTPUT</name>
                  <value>1</value>
                </enumeratedValue>
              </enumeratedValues>
            </field>
          </fields>
        </register>
        <register>
          <name>IDR</name>
          <description>Port input data</description>
          <addressOffset>0x8</addressOffset>
          <access>read-only</access>
        </register>
      </registers>
"#,
            "",
        );
        let map = parse(&text).expect("the file reads");
        let p = &map.peripherals[0];
        assert!(p.registers.is_empty());
        assert_eq!(segments(p)[0].size, 0x400, "the block still maps");
        assert_eq!(struct_size(p), 0x400);
    }
}
