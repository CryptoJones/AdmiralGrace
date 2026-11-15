//! Read IDA databases (`.idb`, `.i64`) and type libraries (`.til`): the
//! names, comments and types an analyst worked out in IDA, brought into a
//! project without typing them in again (#403).
//!
//! The format is read here from the file up: [`inflate`] decompresses the
//! sections, [`container`] reads the database header and its B-tree index,
//! [`netnode`] reads the key/value nodes the names and comments live in,
//! [`til`] reads a type library, [`types`] deserializes IDA's packed types
//! into C, and [`extract`] gathers the whole into the names, comments,
//! functions, segments and types a project applies.
//!
//! The layout follows python-idb (Willi Ballenthin, Apache-2.0), whose
//! test databases are the fixtures under `tests/fixtures/ida`; see the
//! README there and NOTICE for attribution.

pub mod container;
pub mod extract;
pub mod inflate;
pub mod netnode;
pub mod til;
pub mod types;
