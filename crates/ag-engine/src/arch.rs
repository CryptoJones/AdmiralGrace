//! What the language id of an image says about the program it holds.
//!
//! The loader resolves a SLEIGH language id for every image it reads, and
//! that id names the architecture, the endianness, the width of the program
//! and the compiler it was built with: `x86:LE:64:default:gcc`. The width is
//! what the decoder has to be told, because x86 has a 16-bit, a 32-bit and a
//! 64-bit encoding and they do not read the same bytes the same way.

/// The width of a program: the size of its pointers and of its instruction
/// pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bitness {
    /// A 16-bit program: a two-byte pointer, `ip`.
    Bits16,
    /// A 32-bit program: a four-byte pointer, `eip`.
    Bits32,
    /// A 64-bit program: an eight-byte pointer, `rip`.
    Bits64,
}

impl Bitness {
    /// The width in bits.
    pub const fn bits(self) -> u32 {
        match self {
            Bitness::Bits16 => 16,
            Bitness::Bits32 => 32,
            Bitness::Bits64 => 64,
        }
    }

    /// The width in bytes: the size of a pointer of the program.
    pub const fn byte_size(self) -> u64 {
        (self.bits() / 8) as u64
    }

    /// The bitness a language id names, when it names one.
    ///
    /// The id spells the width as a field of its own — the third one,
    /// `x86:LE:32:default:gcc` — so that is the field that is read. An id
    /// with no width field, or one that is not a width the decoder knows,
    /// names none.
    pub fn of_language(language: &str) -> Option<Bitness> {
        match language.split(':').nth(2)? {
            "16" => Some(Bitness::Bits16),
            "32" => Some(Bitness::Bits32),
            "64" => Some(Bitness::Bits64),
            _ => None,
        }
    }

    /// Whether a language id names x86, of any width.
    ///
    /// The id of x86 starts with the architecture and a colon: `x86:LE:64:...`.
    pub fn is_x86(language: &str) -> bool {
        language.starts_with("x86:")
    }
}

impl std::fmt::Display for Bitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-bit", self.bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_width_of_a_language_is_read_from_its_id() {
        assert_eq!(
            Bitness::of_language("x86:LE:64:default:gcc"),
            Some(Bitness::Bits64)
        );
        assert_eq!(
            Bitness::of_language("x86:LE:32:default:gcc"),
            Some(Bitness::Bits32)
        );
        assert_eq!(
            Bitness::of_language("x86:LE:64:default:windows"),
            Some(Bitness::Bits64)
        );
        assert_eq!(
            Bitness::of_language("x86:LE:16:Real Mode:default"),
            Some(Bitness::Bits16)
        );
    }

    #[test]
    fn a_language_that_names_no_width_has_none() {
        assert_eq!(Bitness::of_language("PowerPC:BE:default:ppc"), None);
        assert_eq!(Bitness::of_language("x86:LE"), None);
        assert_eq!(Bitness::of_language(""), None);
    }

    #[test]
    fn the_width_of_a_language_of_another_architecture_is_read_too() {
        // The width is a field of the id, whatever the architecture is.
        assert_eq!(Bitness::of_language("ARM:LE:32:v8"), Some(Bitness::Bits32));
    }

    #[test]
    fn a_pointer_is_as_many_bytes_as_the_width_says() {
        assert_eq!(Bitness::Bits16.byte_size(), 2);
        assert_eq!(Bitness::Bits32.byte_size(), 4);
        assert_eq!(Bitness::Bits64.byte_size(), 8);
        assert_eq!(Bitness::Bits32.bits(), 32);
        assert_eq!(Bitness::Bits32.to_string(), "32-bit");
    }

    #[test]
    fn x86_is_recognized_by_its_language_id() {
        assert!(Bitness::is_x86("x86:LE:64:default:gcc"));
        assert!(Bitness::is_x86("x86:LE:32:default:gcc"));
        assert!(!Bitness::is_x86("ARM:LE:32:v8"));
        assert!(!Bitness::is_x86("x86ish"));
    }
}
