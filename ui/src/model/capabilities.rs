//! Which analysis results the active project can actually produce.
//!
//! Views consult these flags instead of assuming every project has every
//! artifact, so an incomplete backend degrades into an explained empty state
//! rather than a blank panel.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Linear disassembly of a function body.
    pub listing: bool,
    /// Decompiled pseudocode.
    pub pseudocode: bool,
    /// Control-flow graph rendering.
    pub graph: bool,
    /// Raw byte access.
    pub bytes: bool,
    /// Cross references to and from an address.
    pub references: bool,
    /// Extracted strings.
    pub strings: bool,
    /// File segments / sections.
    pub segments: bool,
    /// Imported symbols.
    pub imports: bool,
    /// Exported symbols.
    pub exports: bool,
    /// Recovered type information.
    pub types: bool,
    /// Analyst bookmarks.
    pub bookmarks: bool,
    /// Objective-C method overlays.
    pub objc_methods: bool,
}

impl Capabilities {
    /// No analysis artifacts at all.
    pub const NONE: Self = Self {
        listing: false,
        pseudocode: false,
        graph: false,
        bytes: false,
        references: false,
        strings: false,
        segments: false,
        imports: false,
        exports: false,
        types: false,
        bookmarks: false,
        objc_methods: false,
    };
}
