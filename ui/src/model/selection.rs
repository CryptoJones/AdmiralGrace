//! The single shared selection every view synchronizes against.

/// What the analyst currently has selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// A function, identified by its entry address.
    Function(u64),
    /// A single address inside a function or a data region.
    Address(u64),
    /// A run of bytes.
    #[allow(dead_code)]
    ByteRange { start: u64, len: usize },
    /// Nothing selected.
    None,
}

impl Selection {
    /// The address the selection anchors on, if any.
    pub fn address(&self) -> Option<u64> {
        match self {
            Selection::Function(addr) | Selection::Address(addr) => Some(*addr),
            Selection::ByteRange { start, .. } => Some(*start),
            Selection::None => None,
        }
    }

    /// A short human-readable description for the status bar.
    pub fn describe(&self) -> String {
        match self {
            Selection::Function(addr) => format!("function {addr:#x}"),
            Selection::Address(addr) => format!("address {addr:#x}"),
            Selection::ByteRange { start, len } => format!("{len} bytes at {start:#x}"),
            Selection::None => "no selection".into(),
        }
    }
}
