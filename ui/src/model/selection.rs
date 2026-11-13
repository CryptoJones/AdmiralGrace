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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_anchors_on_its_address() {
        assert_eq!(Selection::Function(0x1000).address(), Some(0x1000));
        assert_eq!(Selection::Address(0x1004).address(), Some(0x1004));
        assert_eq!(
            Selection::ByteRange {
                start: 0x2000,
                len: 4
            }
            .address(),
            Some(0x2000)
        );
        assert_eq!(Selection::None.address(), None);
    }

    #[test]
    fn the_status_text_names_the_kind() {
        assert_eq!(Selection::Function(0x10).describe(), "function 0x10");
        assert_eq!(
            Selection::ByteRange { start: 0x20, len: 3 }.describe(),
            "3 bytes at 0x20"
        );
        assert_eq!(Selection::None.describe(), "no selection");
    }
}
