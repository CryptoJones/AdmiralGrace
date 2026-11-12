//! Library identification by whole-function hash (#394).
//!
//! A library function — `strlen`, `std::string::_M_create`, `__udivdi3` —
//! is the same code in every program that links it, so it can be recognised
//! by a fingerprint of its body and named without the analyst lifting a
//! line. This module computes that fingerprint, reads and writes the
//! signature files that hold it, and matches a function against them.
//!
//! # The hash, and its constraints
//!
//! The fingerprint is a SHA-256 over the function's bytes, but not its bytes
//! as they sit in one image: a function compiled into a shared library is
//! position-independent, and the operands that name an address change with
//! the load address and the link layout while the code does not. Hashing
//! those bytes would give the same function a different fingerprint in every
//! program. So before hashing, the **constraints** mask them — the bytes that
//! carry an address are zeroed, and only the address-independent code is
//! hashed:
//!
//! - the target offset of a relative branch — a `call`, a `jmp`, a `jcc`, a
//!   `loop` — whose displacement is the distance to another function or
//!   block, not the function's own code;
//! - the displacement of a memory operand that names an address: a
//!   RIP-relative `[rip+0x…]` (the way PIC code reaches its globals and its
//!   GOT), or an absolute `[0x804b008]` with no base and no index.
//!
//! A displacement that is an offset into a structure or a stack frame —
//! `[rbp-0x8]`, `[rax+0x10]` — is left as it is: it is the same in every
//! image, and masking it would throw away what tells two functions apart.
//! The masking is read off the decoded instructions ([`normalize`]), so it
//! needs no relocation table and is the same whether the signature is made
//! or matched. On x86 the spans come from the decoder's own constant offsets,
//! so a short branch's one-byte offset and a near branch's four are each
//! masked exactly. An architecture the masker does not read is hashed as it
//! stands, without constraints.
//!
//! The hash is domain-separated by a version tag, the architecture and the
//! byte length, so a function never matches a signature of another width or
//! another length, and a future change to the constraints cannot be mistaken
//! for the old one.
//!
//! # The signature file
//!
//! A signature file (`.agsig`) is JSON: a library's name, its architecture,
//! where it came from, and one [`Signature`] a function — the hash, the byte
//! length, the name, and, when they are known, the C prototype and a comment.
//! [`SignatureDb`] reads and writes it; [`SignatureSet`] holds several and
//! answers a hash — the first carrier wins, and every carrier is offered as
//! a [`Candidate`] so a chooser can pick between them. The engine ships
//! three built-ins ([`SignatureSet::builtin`]): libc, libstdc++ and libgcc,
//! generated from the reference builds named in each file's `source`.
//! `ag funcid create` makes a new one from any image
//! whose functions are named; `ag funcid match` and `ag funcid apply` read
//! them back onto an image. See `docs/funcid.md`.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::arch::Bitness;

/// The signature-file format this module reads and writes.
pub const FORMAT: u32 = 1;

/// The domain separator hashed ahead of every function, so a fingerprint is
/// never read as another kind of hash and a change to the constraints is a
/// change to the tag.
const DOMAIN: &[u8] = b"admiralgrace-funcid-v1\0";

/// The built-in libc signatures: the C library's functions, by whole-function
/// hash, generated from the reference build the file names.
pub const LIBC: &str = include_str!("funcid/libc.agsig");
/// The built-in libstdc++ signatures: the GNU C++ standard library.
pub const LIBSTDCXX: &str = include_str!("funcid/libstdc++.agsig");
/// The built-in libgcc signatures: the GCC low-level run-time — the soft
/// arithmetic, the unwinder, the TLS helpers.
pub const LIBGCC: &str = include_str!("funcid/libgcc.agsig");

/// The architecture tag a language id names: `x86:LE:64:default:gcc` is
/// `x86-64`, `x86:LE:32:default` is `x86`, `AARCH64:LE:64:v8A` is `aarch64`.
/// The tag is what a signature file's `arch` holds and what [`function_hash`]
/// reads to choose its constraints; the x86 family is masked, the rest hashed
/// as they stand.
pub fn arch_of_language(language: &str) -> String {
    let processor = language
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let bits = Bitness::of_language(language).map(Bitness::bits);
    match (processor.as_str(), bits) {
        ("x86", Some(64)) => "x86-64".to_string(),
        ("x86", Some(32)) => "x86".to_string(),
        ("x86", Some(16)) => "x86-16".to_string(),
        ("aarch64", _) => "aarch64".to_string(),
        ("arm", _) => "arm".to_string(),
        _ => processor,
    }
}

/// The function's bytes with the address-dependent operands masked out — the
/// constraints of [`function_hash`]. `base` is the address the bytes sit at,
/// which the x86 decoder reads to tell a RIP-relative operand from any other;
/// the mask itself does not depend on its value, so the same code at two load
/// addresses normalizes to the same bytes. An architecture other than x86 is
/// returned unchanged.
pub fn normalize(arch: &str, bytes: &[u8], base: u64) -> Vec<u8> {
    let bitness = match arch {
        "x86-64" => 64,
        "x86" => 32,
        _ => return bytes.to_vec(),
    };
    let mut out = bytes.to_vec();
    let mut decoder =
        iced_x86::Decoder::with_ip(bitness, bytes, base, iced_x86::DecoderOptions::NONE);
    let mut instruction = iced_x86::Instruction::new();
    while decoder.can_decode() {
        let start = decoder.position();
        decoder.decode_out(&mut instruction);
        let offsets = decoder.get_constant_offsets(&instruction);
        // A relative branch's target is its immediate: the distance to
        // another function or block, which the link layout decides.
        if is_branch(&instruction) && offsets.has_immediate() {
            zero(
                &mut out,
                start + offsets.immediate_offset(),
                offsets.immediate_size(),
            );
        }
        // A memory displacement that names an address — RIP-relative, or
        // absolute with no base and no index — moves with the load address.
        if offsets.has_displacement() && displacement_is_address(&instruction) {
            zero(
                &mut out,
                start + offsets.displacement_offset(),
                offsets.displacement_size(),
            );
        }
    }
    out
}

/// Whether the instruction's first operand is a branch target — a relative
/// `call`/`jmp`/`jcc`/`loop` or a far branch — whose offset the constraints
/// mask. An indirect call or jump through a register or a GOT slot is not
/// one: its target is not an immediate, and a GOT slot's displacement is
/// masked as an address instead.
fn is_branch(instruction: &iced_x86::Instruction) -> bool {
    use iced_x86::OpKind;
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16
            | OpKind::NearBranch32
            | OpKind::NearBranch64
            | OpKind::FarBranch16
            | OpKind::FarBranch32
    )
}

/// Whether a memory operand's displacement names an address rather than an
/// offset into a structure or a frame: a RIP-relative operand, or an absolute
/// one with no base register, no index and no segment override. `fs:[0x28]`
/// is the stack guard, not an address in the program, so a segment override
/// takes the operand out of the flat address space and leaves it unmasked.
fn displacement_is_address(instruction: &iced_x86::Instruction) -> bool {
    use iced_x86::Register as R;
    if instruction.is_ip_rel_memory_operand() {
        return true;
    }
    let has_memory =
        (0..instruction.op_count()).any(|i| instruction.op_kind(i) == iced_x86::OpKind::Memory);
    has_memory
        && instruction.memory_base() == R::None
        && instruction.memory_index() == R::None
        && instruction.segment_prefix() == R::None
}

/// Zero `len` bytes of `out` at `at`, clamped to its end: a decoder's span
/// always falls inside the instruction, but a malformed tail must not panic.
fn zero(out: &mut [u8], at: usize, len: usize) {
    let end = at.saturating_add(len).min(out.len());
    for byte in &mut out[at.min(end)..end] {
        *byte = 0;
    }
}

/// The whole-function hash of `bytes` under `arch`: a SHA-256, as lower-case
/// hex, over the domain tag, the architecture, the byte length and the
/// constrained bytes ([`normalize`]). `base` is the address the bytes sit at.
/// The same function at two load addresses hashes the same; a function of
/// another architecture or another length never does.
pub fn function_hash(arch: &str, bytes: &[u8], base: u64) -> String {
    let masked = normalize(arch, bytes, base);
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(arch.as_bytes());
    hasher.update([0]);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(&masked);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// One function's signature: its whole-function hash and what a match knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// The whole-function hash, as [`function_hash`] writes it.
    pub hash: String,
    /// The function's length in bytes, as the hash was taken over.
    pub length: u64,
    /// The name the match gives the function.
    pub name: String,
    /// The C prototype the match applies, when it is known:
    /// `size_t strlen(const char *s)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    /// The comment the match leaves on the function, when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// One library's signature file: its name, its architecture, where it came
/// from, and its signatures. The JSON form is what `.agsig` holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureDb {
    /// The format version; [`FORMAT`] is what this module writes.
    pub format: u32,
    /// The library's name: `libc`, `libstdc++`, `libgcc`.
    pub library: String,
    /// The architecture the signatures were taken under: `x86-64`, `x86`.
    pub arch: String,
    /// Where the signatures came from — the build they were generated from —
    /// when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The signatures, one a function.
    pub signatures: Vec<Signature>,
}

impl SignatureDb {
    /// An empty database for `library` under `arch`.
    pub fn new(library: &str, arch: &str) -> SignatureDb {
        SignatureDb {
            format: FORMAT,
            library: library.to_string(),
            arch: arch.to_string(),
            source: None,
            signatures: Vec::new(),
        }
    }

    /// Read a signature file's JSON. A format newer than this module knows is
    /// refused, not misread.
    pub fn parse(source: &str) -> Result<SignatureDb, String> {
        let db: SignatureDb =
            serde_json::from_str(source).map_err(|e| format!("not a signature file: {e}"))?;
        if db.format > FORMAT {
            return Err(format!(
                "signature format {} is newer than this program reads ({FORMAT})",
                db.format
            ));
        }
        Ok(db)
    }

    /// Write the database as the JSON a `.agsig` file holds, with a trailing
    /// newline.
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// How many signatures the database holds.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Whether the database holds no signatures.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

/// One signature a hash names, with the library that carries it. Several
/// databases can carry the same hash — two builds of one library, a thunk
/// and its target under different names — and the analyst chooses between
/// them ([`SignatureSet::candidates`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate<'a> {
    /// The library the signature came from: `libc`, `libstdc++`.
    pub library: &'a str,
    /// The signature itself.
    pub signature: &'a Signature,
}

/// Several signature databases, indexed by hash so a match is one lookup. The
/// first database to carry a hash wins, the way the type libraries answer in
/// order; every carrier of the hash is kept, so a chooser can offer them all.
#[derive(Debug, Clone)]
pub struct SignatureSet {
    /// The databases, in the order they are consulted.
    pub databases: Vec<SignatureDb>,
    /// Each hash to every database and signature that carry it, in the
    /// order the databases are consulted.
    by_hash: BTreeMap<String, Vec<(usize, usize)>>,
}

impl SignatureSet {
    /// Index `databases` by hash.
    pub fn new(databases: Vec<SignatureDb>) -> SignatureSet {
        let mut by_hash: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
        for (db, database) in databases.iter().enumerate() {
            for (sig, signature) in database.signatures.iter().enumerate() {
                by_hash
                    .entry(signature.hash.clone())
                    .or_default()
                    .push((db, sig));
            }
        }
        SignatureSet { databases, by_hash }
    }

    /// The built-in signatures — libc, libstdc++ and libgcc — read once.
    pub fn builtin() -> Arc<SignatureSet> {
        static CACHE: OnceLock<Arc<SignatureSet>> = OnceLock::new();
        Arc::clone(CACHE.get_or_init(|| {
            let databases = [LIBC, LIBSTDCXX, LIBGCC]
                .iter()
                .filter_map(|source| SignatureDb::parse(source).ok())
                .collect();
            Arc::new(SignatureSet::new(databases))
        }))
    }

    /// The signature a hash names, when any database carries it: the first
    /// carrier's, the way the type libraries answer in order. Every carrier
    /// is offered by [`SignatureSet::candidates`].
    pub fn by_hash(&self, hash: &str) -> Option<&Signature> {
        let &(db, sig) = self.by_hash.get(hash)?.first()?;
        self.databases.get(db)?.signatures.get(sig)
    }

    /// Every signature a hash names, each with its library, in the order the
    /// databases are consulted. The first is what [`SignatureSet::by_hash`]
    /// names; the rest are the alternatives a chooser offers. Empty when no
    /// database carries the hash.
    pub fn candidates(&self, hash: &str) -> Vec<Candidate<'_>> {
        let Some(carriers) = self.by_hash.get(hash) else {
            return Vec::new();
        };
        carriers
            .iter()
            .filter_map(|&(db, sig)| {
                let database = self.databases.get(db)?;
                Some(Candidate {
                    library: &database.library,
                    signature: database.signatures.get(sig)?,
                })
            })
            .collect()
    }

    /// The signature the function `bytes` under `arch` at `base` matches, by
    /// its whole-function hash. `None` when no database knows the function.
    pub fn match_function(&self, arch: &str, bytes: &[u8], base: u64) -> Option<&Signature> {
        let hash = function_hash(arch, bytes, base);
        self.by_hash(&hash)
    }

    /// Every signature the function `bytes` under `arch` at `base` matches,
    /// each with its library, in the order the databases are consulted. The
    /// first is what [`SignatureSet::match_function`] names. Empty when no
    /// database knows the function.
    pub fn match_candidates(&self, arch: &str, bytes: &[u8], base: u64) -> Vec<Candidate<'_>> {
        let hash = function_hash(arch, bytes, base);
        self.candidates(&hash)
    }

    /// How many signatures the set holds across its databases.
    pub fn len(&self) -> usize {
        self.databases.iter().map(SignatureDb::len).sum()
    }

    /// Whether the set holds no signatures.
    pub fn is_empty(&self) -> bool {
        self.databases.is_empty() || self.databases.iter().all(SignatureDb::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble x86-64 code at `base`, one instruction a line, with the
    /// engine's own assembler, so a test's code is real code and not a
    /// hand-typed guess. Each instruction is encoded at the address it falls
    /// at, the way it would sit in an image.
    fn asm(text: &str, base: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = base;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let bytes =
                crate::asm::assemble(line, at, Bitness::Bits64).expect("the test assembles");
            at += bytes.len() as u64;
            out.extend_from_slice(&bytes);
        }
        out
    }

    #[test]
    fn a_branch_offset_is_masked_but_the_code_is_not() {
        // call rel32; ret — E8 FB 0E 00 00 C3. The call's four-byte offset
        // is an address; the opcode and the ret are the function's own code.
        let bytes = [0xE8, 0xFB, 0x0E, 0x00, 0x00, 0xC3];
        let masked = normalize("x86-64", &bytes, 0x100);
        assert_eq!(masked.len(), bytes.len());
        assert_eq!(masked[0], 0xE8);
        assert_eq!(&masked[1..5], &[0, 0, 0, 0]);
        assert_eq!(masked[5], 0xC3);
        // The original offset is not all zero, so the mask did something.
        assert_ne!(&bytes[1..5], &[0, 0, 0, 0]);
    }

    #[test]
    fn a_short_branch_masks_one_byte_and_a_near_branch_four() {
        // jmp short over a nop: EB 01 90 — the one-byte offset is masked,
        // the nop after it stands.
        let short = [0xEB, 0x01, 0x90];
        let masked = normalize("x86-64", &short, 0x100);
        assert_eq!(masked, [0xEB, 0x00, 0x90]);
        // A near jump: E9 followed by four offset bytes, all masked.
        let near = [0xE9, 0xFB, 0x1E, 0x00, 0x00, 0xC3];
        let masked = normalize("x86-64", &near, 0x100);
        assert_eq!(masked[0], 0xE9);
        assert_eq!(&masked[1..5], &[0, 0, 0, 0]);
        assert_eq!(masked[5], 0xC3);
    }

    #[test]
    fn a_rip_relative_displacement_is_masked_but_a_frame_offset_is_not() {
        // mov rax, [rip+0x1234]; ret — 48 8B 05 34 12 00 00 C3. The
        // displacement names a global, so it is masked.
        let rip = [0x48, 0x8B, 0x05, 0x34, 0x12, 0x00, 0x00, 0xC3];
        let masked = normalize("x86-64", &rip, 0x100);
        assert_eq!(&masked[..3], &rip[..3]);
        assert_eq!(&masked[3..7], &[0, 0, 0, 0]);
        assert_eq!(masked[7], 0xC3);
        // mov rax, [rbp-0x8]; ret — 48 8B 45 F8 C3. A frame offset is the
        // same in every image, so it is kept.
        let frame = [0x48, 0x8B, 0x45, 0xF8, 0xC3];
        let masked = normalize("x86-64", &frame, 0x100);
        assert_eq!(masked, frame, "a frame offset is kept");
    }

    #[test]
    fn the_hash_is_the_same_at_two_load_addresses() {
        // The same call to a fixed target, assembled at two bases within a
        // branch's reach: the relative offset differs with the base, so the
        // bytes differ, but the constraints mask it and the hash does not
        // move with the image.
        let low = asm("call 0x20000000\nret", 0x1000);
        let high = asm("call 0x20000000\nret", 0x10000000);
        assert_ne!(low, high, "the two bases encode the call differently");
        assert_eq!(
            function_hash("x86-64", &low, 0x1000),
            function_hash("x86-64", &high, 0x10000000),
        );
    }

    #[test]
    fn different_code_hashes_differently() {
        let a = asm("xor eax, eax\nret", 0x100);
        let b = asm("mov eax, 1\nret", 0x100);
        assert_ne!(
            function_hash("x86-64", &a, 0x100),
            function_hash("x86-64", &b, 0x100),
        );
        // The length is hashed too: a nop padded onto the same code is a
        // different signature.
        let padded = asm("xor eax, eax\nnop\nret", 0x100);
        assert_ne!(
            function_hash("x86-64", &a, 0x100),
            function_hash("x86-64", &padded, 0x100),
        );
    }

    #[test]
    fn another_architecture_is_hashed_as_it_stands() {
        let bytes = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(normalize("aarch64", &bytes, 0), bytes.to_vec());
        // Still a stable, domain-separated hash.
        let hash = function_hash("aarch64", &bytes, 0);
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, function_hash("aarch64", &bytes, 0));
        assert_ne!(hash, function_hash("x86-64", &bytes, 0));
    }

    #[test]
    fn a_signature_file_round_trips() {
        let mut db = SignatureDb::new("libc", "x86-64");
        db.source = Some("reference build".to_string());
        db.signatures.push(Signature {
            hash: function_hash("x86-64", &asm("xor eax, eax\nret", 0), 0),
            length: 3,
            name: "zero".to_string(),
            prototype: Some("int zero(void)".to_string()),
            comment: Some("returns 0".to_string()),
        });
        let text = db.to_json();
        let read = SignatureDb::parse(&text).expect("round trips");
        assert_eq!(read, db);
    }

    #[test]
    fn a_newer_format_is_refused() {
        let text = r#"{"format":99,"library":"x","arch":"x86-64","signatures":[]}"#;
        assert!(SignatureDb::parse(text).is_err());
        assert!(SignatureDb::parse("not json").is_err());
    }

    #[test]
    fn a_set_matches_a_function_by_its_hash() {
        let bytes = asm("xor eax, eax\nret", 0x100);
        let hash = function_hash("x86-64", &bytes, 0x100);
        let mut db = SignatureDb::new("libc", "x86-64");
        db.signatures.push(Signature {
            hash: hash.clone(),
            length: bytes.len() as u64,
            name: "zero".to_string(),
            prototype: None,
            comment: None,
        });
        let set = SignatureSet::new(vec![db]);
        let matched = set
            .match_function("x86-64", &bytes, 0x100)
            .expect("matches");
        assert_eq!(matched.name, "zero");
        assert!(set.by_hash(&hash).is_some());
        // The same code at another base still matches.
        assert!(set.match_function("x86-64", &bytes, 0x9000).is_some());
        // Other code does not.
        let other = asm("mov eax, 1\nret", 0x100);
        assert!(set.match_function("x86-64", &other, 0x100).is_none());
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn every_carrier_of_a_hash_is_a_candidate_in_consultation_order() {
        let bytes = asm("xor eax, eax\nret", 0x100);
        let hash = function_hash("x86-64", &bytes, 0x100);
        let signature = |name: &str| Signature {
            hash: hash.clone(),
            length: bytes.len() as u64,
            name: name.to_string(),
            prototype: None,
            comment: None,
        };
        let mut first = SignatureDb::new("libc", "x86-64");
        first.signatures.push(signature("zero"));
        let mut second = SignatureDb::new("aliases", "x86-64");
        second.signatures.push(signature("nullsub"));
        // A database that knows other code, consulted between the two, does
        // not disturb their order.
        let mut other = SignatureDb::new("libgcc", "x86-64");
        other.signatures.push(Signature {
            hash: function_hash("x86-64", &asm("mov eax, 1\nret", 0x100), 0x100),
            length: 6,
            name: "one".to_string(),
            prototype: None,
            comment: None,
        });
        let set = SignatureSet::new(vec![first, other, second]);

        // The first carrier still wins the single-answer lookups.
        assert_eq!(set.by_hash(&hash).expect("matches").name, "zero");
        assert_eq!(
            set.match_function("x86-64", &bytes, 0x100)
                .expect("matches")
                .name,
            "zero"
        );

        // Every carrier is offered, with its library, in consultation order.
        let candidates = set.match_candidates("x86-64", &bytes, 0x100);
        let named: Vec<(&str, &str)> = candidates
            .iter()
            .map(|c| (c.library, c.signature.name.as_str()))
            .collect();
        assert_eq!(named, [("libc", "zero"), ("aliases", "nullsub")]);
        assert_eq!(set.candidates(&hash), candidates);

        // Code no database knows has no candidates.
        let unknown = asm("mov eax, 2\nret", 0x100);
        assert!(set.match_candidates("x86-64", &unknown, 0x100).is_empty());
        assert!(set.candidates("not a hash").is_empty());
    }

    #[test]
    fn the_builtin_libraries_load_and_carry_their_names() {
        let set = SignatureSet::builtin();
        assert!(!set.is_empty(), "the shipped databases are not empty");
        for name in ["libc", "libstdc++", "libgcc"] {
            let db = set
                .databases
                .iter()
                .find(|db| db.library == name)
                .unwrap_or_else(|| panic!("the built-ins carry {name}"));
            assert!(!db.is_empty(), "{name} has signatures");
            assert_eq!(db.arch, "x86-64");
            for sig in &db.signatures {
                assert_eq!(sig.hash.len(), 64, "{} hash is a SHA-256", sig.name);
                assert!(sig.length > 0, "{} has a length", sig.name);
            }
        }
        // libc's malloc is among them, and a match returns its prototype.
        let malloc = set
            .databases
            .iter()
            .find(|db| db.library == "libc")
            .unwrap()
            .signatures
            .iter()
            .find(|sig| sig.name == "malloc")
            .expect("libc ships malloc");
        assert!(malloc.prototype.is_some());
    }

    #[test]
    fn the_architecture_tag_reads_the_language() {
        assert_eq!(arch_of_language("x86:LE:64:default:gcc"), "x86-64");
        assert_eq!(arch_of_language("x86:LE:32:default"), "x86");
        assert_eq!(arch_of_language("AARCH64:LE:64:v8A:default"), "aarch64");
        assert_eq!(arch_of_language("ARM:LE:32:v8:default"), "arm");
    }
}
