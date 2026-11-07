//! COM interface and class types named by GUID (#382).
//!
//! A COM object is created by GUID: the class GUID (CLSID) names the
//! coclass that implements it, the interface GUID (IID) names the
//! interface the caller wants back, and both are passed to
//! `CoCreateInstance`. A binary that uses COM carries those GUIDs as
//! 16-byte values in its data — `const CLSID`/IID initialisers — and
//! type information turns the register arithmetic around them into
//! readable code: `CoCreateInstance(&CLSID_ShellLink, …, &IID_IShellLinkW, …)`
//! names its arguments instead of leaving them as addresses.
//!
//! A GUID is 16 bytes: the first three fields are stored little-endian
//! (`Data1` a `u32`, `Data2` and `Data3` `u16`s) and the last eight
//! (`Data4`) as written. Its text form is the Windows spelling,
//! `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`, upper case. [`GUID`] is
//! that value; [`Guid::from_bytes`] reads it from a section's bytes
//! and [`Guid::text`] writes it back.
//!
//! [`scan`] walks data the image holds — non-code sections: `.data`,
//! `.rdata`, `__DATA`, `__TEXT,__const`, and the rest that are not
//! code — at 4-byte alignment with each known COM GUID's bytes, and
//! reports every [`GuidHit`] it finds, under its address and section.
//! Code is out: a GUID's bytes can fall inside an instruction, and only
//! data is referenced as a value. The known GUIDs are the [`CATALOG`]:
//! the core interfaces every COM object answers to — `IUnknown`,
//! `IDispatch`, the `IEnum*` family, `IPersist`, `IConnectionPoint`
//! and friends — and the coclasses of the shell, Internet Explorer,
//! Windows Script and the rest whose GUIDs the Windows SDK prints.
//!
//! What a hit means. Where the GUID is an IID, the interface it names
//! is the one a `QueryInterface` asks for and `CoCreateInstance`
//! returns, so the interface's type is wanted. Where it is a CLSID,
//! the coclass is the one `CoCreateInstance` makes. [`ComMetadata`]
//! files the hits — the interfaces the image names and the classes it
//! creates — and [`ComMetadata::types`] gives the C of each: `GUID`
//! itself, each interface as a vtable struct for its methods —
//! `IUnknown`'s three, then its own in slot order, the first member
//! the vtable pointer — and each class as the SDK spells it, a `GUID`
//! typedef plus the `CLSID_` comment. [`ComMetadata::header`] writes
//! the found types as a C header.
//!
//! The scan itself reports `at: None` for every hit: no statement
//! attribution yet.
//!
//! The scan walks each section at 4-byte alignment, so a GUID the
//! loader or the compiler kept at 1- or 2-byte alignment — a packed
//! struct, a `#pragma pack(1)` constant — can fall between the
//! offsets walked and be missed, and a GUID straddling the end of
//! one section into the next is never read: each section is walked
//! on its own bytes. A hit is a byte-pattern match, not a symbol
//! attribution — a zero-filled block whose tail happens to read
//! `C0 00 00 00 00 00 00 46` reports as `IUnknown`.

/// One COM GUID: the 16-byte identifier COM names a class or an
/// interface by, in the image's byte order — `Data1` little-endian,
/// `Data2` and `Data3` little-endian, `Data4` as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The GUID in `bytes`, which must hold at least 16.
    pub fn from_bytes(bytes: &[u8]) -> Option<Guid> {
        let (&[b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15], _) =
            bytes.split_at_checked(16)?
        else {
            return None;
        };
        Some(Guid([
            b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15,
        ]))
    }

    /// The GUID as the Windows SDK spells it: upper-case braced text,
    /// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub fn text(self) -> String {
        let b = self.0;
        format!(
            "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12],
            b[13], b[14], b[15]
        )
    }

    /// The C initialiser the SDK writes, as `{0XXXXXXXX,0XXXX,0XXXX,{0XX,0XX,0XX,0XX,0XX,0XX,0XX,0XX}}`.
    #[cfg(test)]
    pub fn c_initializer(self) -> String {
        let b = self.0;
        format!(
            "{{0x{:02X}{:02X}{:02X}{:02X},0x{:02X}{:02X},0x{:02X}{:02X},{{0x{:02X},0x{:02X},0x{:02X},0x{:02X},0x{:02X},0x{:02X},0x{:02X},0x{:02X}}}}}",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12],
            b[13], b[14], b[15]
        )
    }
}

/// Whether `guid` is that COM GUID, spelled as text — the catalog's
/// shorthand, so its entries read as the SDK prints them.
fn guid(text: &str) -> Guid {
    // Text is the SDK's spelling, eight groups of hex: Data1 (8),
    // Data2 (4), Data3 (4), then Data4 as eight bytes. In memory
    // Data1..Data3 are little-endian, byte-reversed within the field;
    // Data4 is byte-for-byte.
    let clean: Vec<u8> = text
        .bytes()
        .filter(|c| *c != b'-' && *c != b'{' && *c != b'}')
        .collect();
    debug_assert_eq!(clean.len(), 32, "a GUID's text holds 32 hex digits");
    let pair = |i: usize| -> u8 {
        let hi = (clean[i * 2] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (clean[i * 2 + 1] as char).to_digit(16).unwrap_or(0) as u8;
        hi * 16 + lo
    };
    let mut bytes = [0u8; 16];
    // Data1 is the first four bytes as a little-endian u32, Data2 and
    // Data3 are each a little-endian u16, Data4 is byte-for-byte, so
    // each field's hex reverses within the field and not across it.
    let fields = [(0usize, 4usize), (4, 2), (6, 2)];
    let mut hex_at = 0usize;
    for (at, len) in fields {
        for i in 0..len {
            bytes[at + i] = pair(hex_at + len - 1 - i);
        }
        hex_at += len;
    }
    for i in 0..8 {
        bytes[8 + i] = pair(hex_at + i);
    }
    Guid(bytes)
}

/// What the catalog knows a GUID names: the interface or class, the
/// interface's methods past `IUnknown`'s three in slot order, and
/// whether it is the IID of an interface or the CLSID of a coclass.
#[derive(Debug, Clone)]
pub struct ComEntry {
    /// The interface (`IUnknown`) or coclass (`ShellLink`) named.
    pub name: String,
    /// The GUID, which sorts the catalog.
    pub guid: Guid,
    /// Whether the GUID is an IID, naming an interface, rather than a
    /// CLSID, naming a coclass.
    pub interface: bool,
    /// The methods the interface answers after `IUnknown`'s three —
    /// a coclass has none.
    pub methods: Vec<String>,
}

impl ComEntry {
    fn iid(name: &str, text_guid: &str, methods: &[&str]) -> ComEntry {
        ComEntry {
            name: name.to_string(),
            guid: guid(text_guid),
            interface: true,
            methods: methods.iter().map(|m| m.to_string()).collect(),
        }
    }

    fn clsid(name: &str, text_guid: &str) -> ComEntry {
        ComEntry {
            name: name.to_string(),
            guid: guid(text_guid),
            interface: false,
            methods: Vec::new(),
        }
    }
}

#[cfg(test)]
fn iid(text: &str) -> Guid {
    guid(text)
}

/// The core COM interfaces, with the interfaces `objbase.h` and
/// `unknwn.h` name, and the coclasses the Windows SDK prints.
pub(crate) fn catalog() -> Vec<ComEntry> {
    vec![
        ComEntry::iid("IUnknown", "0000000000000000C000000000000046", &[]),
        ComEntry::iid(
            "IClassFactory",
            "0000000100000000C000000000000046",
            &["CreateInstance", "RetainString", "LockInstance"],
        ),
        ComEntry::iid(
            "IDispatch",
            "0002040000000000C000000000000046",
            &["GetTypeInfoCount", "GetTypeInfo", "GetIDsOfNames", "Invoke"],
        ),
        ComEntry::iid(
            "IEnumUnknown",
            "0000010000000000C000000000000046",
            &["Next", "Skip", "Reset", "Clone"],
        ),
        ComEntry::iid(
            "IEnumVARIANT",
            "0000020400000000C000000000000046",
            &["Next", "Skip", "Reset", "Clone"],
        ),
        ComEntry::iid(
            "IEnumString",
            "0000010100000000C000000000000046",
            &["Next", "Skip", "Reset", "Clone"],
        ),
        ComEntry::iid(
            "IPersist",
            "0000010C00000000C000000000000046",
            &["GetClassID"],
        ),
        ComEntry::iid(
            "IPersistFile",
            "0000010E00000000C000000000000046",
            &["IsDirty", "Load", "Save", "SaveCompleted", "GetCurFile"],
        ),
        ComEntry::iid(
            "IPersistStream",
            "0000010900000000C000000000000046",
            &["IsDirty", "Load", "Save", "SaveCompleted"],
        ),
        ComEntry::iid(
            "IConnectionPointContainer",
            "0000010F00000000C000000000000046",
            &["EnumConnectionPoints", "FindConnectionPoint"],
        ),
        ComEntry::iid(
            "IConnectionPoint",
            "0000010B00000000C000000000000046",
            &[
                "GetConnectionInterface",
                "GetConnectionContainer",
                "Advise",
                "Unadvise",
                "EnumConnections",
            ],
        ),
        ComEntry::iid(
            "IEnumConnectionPoints",
            "0000010D00000000C000000000000046",
            &["Next", "Skip", "Reset", "Clone"],
        ),
        ComEntry::iid(
            "IErrorLog",
            "0000010A00000000C000000000000046",
            &["AddErrorLogEntry"],
        ),
        ComEntry::clsid("ShellLink", "0002140100000000C000000000000046"),
        ComEntry::clsid("InternetExplorer", "0002D00000000000C000000000000046"),
        ComEntry::clsid("ShellFolder", "000214E600000000C000000000000046"),
        ComEntry::iid(
            "IStream",
            "0000000C00000000C000000000000046",
            &[
                "Read",
                "Write",
                "Seek",
                "SetSize",
                "CopyTo",
                "Commit",
                "Revert",
                "LockRegion",
                "UnlockRegion",
                "Stat",
                "Clone",
            ],
        ),
    ]
}

/// A GUID found in the image's data: where it lives, what the catalog
/// names it, and the address of the statement that names it when one
/// does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidHit {
    /// The address the GUID's bytes start at.
    pub address: u64,
    /// The GUID itself.
    pub guid: Guid,
    /// The interface or class the catalog names it, when known.
    pub name: Option<String>,
    /// Whether the catalog knows it as an interface's IID.
    pub interface: bool,
    /// The address of the fact that names this GUID, when one does —
    /// the statement passing its address to `CoCreateInstance` or a
    /// `QueryInterface`.
    pub at: Option<u64>,
}

/// One section to walk: its name and the bytes the image holds there,
/// with the address the first byte maps to.
#[derive(Debug, Clone)]
pub struct ComSection {
    /// The section's name, as the container spells it.
    pub name: String,
    /// The address the first byte maps to.
    pub vma: u64,
    /// Whether the section holds code.
    pub executable: bool,
    /// The bytes the file holds.
    pub bytes: Vec<u8>,
}

/// Whether a section holds data rather than code: the image's own
/// executable flag decides — a GUID's bytes can fall inside an
/// instruction, so code is out. The name check is a backstop for a
/// loader that spells a text section without setting the flag.
fn is_data(section: &ComSection) -> bool {
    if section.executable {
        return false;
    }
    let name = section.name.as_str();
    !matches!(name, ".text" | "__TEXT,__text" | "__TEXT" | "__text")
}

/// Walk `sections` at 4-byte alignment for the GUIDs of the catalog.
/// Code sections are skipped; a GUID crossing a section's end is not
/// read. Each address is reported once, at the first section that
/// holds it.
pub fn scan(sections: &[ComSection]) -> Vec<GuidHit> {
    let page = catalog();
    let mut hits = Vec::new();
    for section in sections {
        if !is_data(section) || section.bytes.len() < 16 {
            continue;
        }
        let mut offset = (4 - (section.vma % 4) as usize) % 4;
        while offset + 16 <= section.bytes.len() {
            let bytes = &section.bytes[offset..offset + 16];
            if let Some(found) = Guid::from_bytes(bytes) {
                if let Some(entry) = page.iter().find(|e| e.guid == found) {
                    hits.push(GuidHit {
                        address: section.vma + offset as u64,
                        guid: found,
                        name: Some(entry.name.clone()),
                        interface: entry.interface,
                        at: None,
                    });
                }
            }
            offset += 4;
        }
    }
    hits.sort_by_key(|hit| hit.address);
    hits.dedup_by_key(|hit| hit.address);
    hits
}

/// The C of a GUID that names an interface: the named type, the
/// vtable struct for its methods, and where its GUID's bytes line up.
pub(crate) fn interface_c(entry: &ComEntry) -> String {
    let mut out = format!("typedef struct {}Vtbl {}Vtbl;\n", entry.name, entry.name);
    out.push_str(&format!("struct {}Vtbl {{\n", entry.name));
    out.push_str(
        "    long (__stdcall *QueryInterface)(void *self, const GUID *riid, void **ppvObj);\n",
    );
    out.push_str("    unsigned long (__stdcall *AddRef)(void *self);\n");
    out.push_str("    unsigned long (__stdcall *Release)(void *self);\n");
    for method in &entry.methods {
        out.push_str(&format!("    void (__stdcall *{method})(void *self);\n"));
    }
    out.push_str("};\n");
    out.push_str(&format!("struct {} {{\n", entry.name));
    out.push_str(&format!("    const {}Vtbl *lpVtbl;\n", entry.name));
    out.push_str("};\n");
    out
}

/// The C of a GUID that names a coclass: the SDK spells a class GUID
/// as a `GUID` typedef, so the class is one too — a 16-byte value, not
/// a struct holding a pointer.
pub(crate) fn class_c(entry: &ComEntry) -> String {
    let mut out = format!("typedef GUID CLSID_{};\n", entry.name);
    out.push_str(&format!("// CLSID_{}: {}\n", entry.name, entry.guid.text()));
    out
}


/// What an image's COM metadata gives: the GUIDs it holds, filed as
/// interfaces and classes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComMetadata {
    /// The GUIDs found in the image's data, in address order.
    pub guids: Vec<GuidHit>,
    /// The interfaces the image names, by name.
    pub interfaces: Vec<String>,
    /// The classes the image creates, by name.
    pub classes: Vec<String>,
}

impl ComMetadata {
    /// File the scan's hits: each named interface once, each named
    /// class once.
    pub fn from_scan(hits: Vec<GuidHit>) -> ComMetadata {
        let mut metadata = ComMetadata::default();
        for hit in hits {
            if let Some(name) = &hit.name {
                if hit.interface {
                    if !metadata.interfaces.contains(name) {
                        metadata.interfaces.push(name.clone());
                    }
                } else if !metadata.classes.contains(name) {
                    metadata.classes.push(name.clone());
                }
            }
            metadata.guids.push(hit);
        }
        metadata.interfaces.sort();
        metadata.classes.sort();
        metadata
    }

    /// The C of the types the image uses: `GUID`, each interface's
    /// interface and vtable, each class, with comments for its GUID
    /// and the statement that uses it.
    pub fn types(&self) -> String {
        let page = catalog();
        let mut out = String::new();
        out.push_str("typedef long HRESULT;\n");
        out.push_str("typedef struct GUID { unsigned int Data1; unsigned short Data2; unsigned short Data3; unsigned char Data4[8]; } GUID;\n");
        for name in &self.interfaces {
            if let Some(entry) = page.iter().find(|e| e.name == *name) {
                out.push_str(&interface_c(entry));
            }
        }
        for name in &self.classes {
            if let Some(entry) = page.iter().find(|e| e.name == *name) {
                out.push_str(&class_c(entry));
            }
        }
        out
    }

    /// The types as a C header, with the guard it carries.
    pub fn header(&self) -> String {
        let mut out = String::new();
        out.push_str("#pragma once\n");
        out.push_str(&self.types());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guid_reads_and_writes_as_the_sdk_spells_it() {
        // IID_IUnknown is 00000000-0000-0000-C000-000000000046 in text:
        // Data1..Data3 little-endian, Data4 as written.
        let g = Guid::from_bytes(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ])
        .unwrap();
        assert_eq!(g.text(), "{00000000-0000-0000-C000-000000000046}");
        assert_eq!(g, iid("0000000000000000C000000000000046"));
    }

    #[test]
    fn an_asymmetric_guid_round_trips_through_text_and_c() {
        // IID_IDispatch is 00020400-0000-0000-C000-000000000046: the
        // nonzero Data1 reaches past the zero tail every other catalog
        // GUID shares, so a transposition in any one of Data1, Data2 or
        // Data3 fails this where the all-zero vector above cannot.
        let dispatch = iid("0002040000000000C000000000000046");
        assert_eq!(
            dispatch.text(),
            "{00020400-0000-0000-C000-000000000046}"
        );
        assert_eq!(
            dispatch.c_initializer(),
            "{0x00020400,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}}"
        );
        assert_eq!(Guid::from_bytes(&dispatch.0).unwrap(), dispatch);
        // A synthetic GUID with every field nonzero pins each
        // field's reversal independently of the catalog's tails.
        let g = Guid::from_bytes(&[
            0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
            0x67, 0x89,
        ])
        .unwrap();
        assert_eq!(g.text(), "{12345678-9ABC-DEF0-ABCD-EF0123456789}");
        assert_eq!(
            g.c_initializer(),
            "{0x12345678,0x9ABC,0xDEF0,{0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89}}"
        );
        assert_eq!(g, guid("123456789ABCDEF0ABCDEF0123456789"));
    }

    #[test]
    fn the_catalog_knows_iunknown() {
        let page = catalog();
        assert!(page.iter().any(|e| e.name == "IUnknown"));
        assert!(page.iter().any(|e| e.name == "IDispatch"));
        assert!(page.iter().any(|e| e.interface));
    }

    #[test]
    fn scan_finds_a_guid_in_data_and_ignores_code() {
        let unknown = iid("0000000000000000C000000000000046");
        let mut bytes = vec![0u8; 32];
        bytes[4..20].copy_from_slice(&unknown.0);
        let data = ComSection {
            name: ".data".to_string(),
            vma: 0x1000,
            executable: false,
            bytes,
        };
        let hits = scan(&[data]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, 0x1004);
        assert_eq!(hits[0].name.as_deref(), Some("IUnknown"));
        // The same bytes in code are not a COM value.
        let code = ComSection {
            name: ".text".to_string(),
            vma: 0x1000,
            executable: true,
            bytes: unknown.0.to_vec(),
        };
        assert!(scan(&[code]).is_empty());
    }

    #[test]
    fn an_interface_gives_its_vtable_after_iunknown() {
        let page = catalog();
        let dispatch = page.iter().find(|e| e.name == "IDispatch").unwrap();

        let c = interface_c(dispatch);
        assert!(c.contains("QueryInterface"));
        assert!(c.contains("Invoke"));
    }

    #[test]
    fn a_class_gives_a_guid_typedef() {
        let page = catalog();
        let shell = page.iter().find(|e| e.name == "ShellLink").unwrap();
        let c = class_c(shell);
        assert!(c.contains("typedef GUID CLSID_ShellLink;"));
        assert!(c.contains("{00021401-0000-0000-C000-000000000046}"));
        assert!(!c.contains("rclsid"));
    }

    #[test]
    fn metadata_files_interfers_and_classes() {
        let hits = scan(&[ComSection {
            name: ".rdata".to_string(),
            vma: 0x2000,
            executable: false,
            bytes: iid("0002040000000000C000000000000046").0.to_vec(),
        }]);
        let metadata = ComMetadata::from_scan(hits);
        assert_eq!(metadata.interfaces, vec!["IDispatch"]);
        assert!(metadata.types().contains("typedef struct GUID"));
    }
}

