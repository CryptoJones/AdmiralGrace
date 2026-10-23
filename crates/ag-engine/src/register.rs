use std::collections::BTreeSet;
use std::fmt;

pub type RegisterClass = u32;

/// One architectural register, or a slice of one.
///
/// `class` and `index` name the *full* register (`RAX` is GPR 0, `ZMM3` is
/// vector 3), while `bit_size` and `bit_offset` say which part of it this id
/// covers: `EAX` is GPR 0 at offset 0 with 32 bits, `AH` is GPR 0 at offset 8
/// with 8 bits. Two ids are equal only when they cover the same bits, so the
/// width of an operand is part of its identity; [`RegisterId::full`] drops the
/// slice to compare registers as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegisterId {
    pub class: RegisterClass,
    pub index: u32,
    pub bit_size: u32,
    pub bit_offset: u32,
}

impl RegisterId {
    /// A whole register of `bit_size` bits.
    pub const fn new(class: RegisterClass, index: u32, bit_size: u32) -> Self {
        Self {
            class,
            index,
            bit_size,
            bit_offset: 0,
        }
    }

    /// A slice of a register.
    pub const fn slice(class: RegisterClass, index: u32, bit_size: u32, bit_offset: u32) -> Self {
        Self {
            class,
            index,
            bit_size,
            bit_offset,
        }
    }

    /// The full register this id is part of, as a (class, index) key.
    pub const fn full(&self) -> (RegisterClass, u32) {
        (self.class, self.index)
    }

    /// Whether the two ids name the same full register, whatever slice of it.
    pub const fn same_register(&self, other: &RegisterId) -> bool {
        self.class == other.class && self.index == other.index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterValue {
    pub class: RegisterClass,
    pub index: u32,
    pub bit_size: u32,
    pub position: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataFlowLocation {
    pub address: u64,
    pub operand_index: u32,
}

#[derive(Debug, Clone)]
pub struct DataFlowDefinition {
    pub register: RegisterId,
    pub location: Option<DataFlowLocation>,
}

/// A set of full registers.
///
/// Membership is by full register: inserting `AL` and asking for `RAX` says
/// yes, because the set tracks which registers are touched, not which slices.
/// Any index is representable, so nothing aliases.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RegisterSet {
    registers: BTreeSet<(RegisterClass, u32)>,
}

impl RegisterSet {
    pub fn empty() -> Self {
        Self {
            registers: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, r: RegisterId) {
        self.registers.insert(r.full());
    }

    pub fn contains(&self, r: RegisterId) -> bool {
        self.registers.contains(&r.full())
    }

    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.registers.len()
    }

    /// The full registers in the set, as (class, index) keys.
    pub fn iter(&self) -> impl Iterator<Item = (RegisterClass, u32)> + '_ {
        self.registers.iter().copied()
    }

    /// The members of one class as a bit mask, when every index fits in 64 bits.
    ///
    /// `None` when the class has no members, or when an index is 64 or more and
    /// a mask would misrepresent it.
    pub fn mask_for_class(&self, class: RegisterClass) -> Option<u64> {
        let mut mask = 0u64;
        let mut any = false;
        for (c, index) in self.registers.iter().copied() {
            if c != class {
                continue;
            }
            if index >= 64 {
                return None;
            }
            mask |= 1u64 << index;
            any = true;
        }
        any.then_some(mask)
    }
}

impl fmt::Debug for RegisterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegisterSet{:?}", self.registers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_of_one_register_differ_but_share_the_register() {
        let rax = RegisterId::new(1, 0, 64);
        let eax = RegisterId::new(1, 0, 32);
        let ah = RegisterId::slice(1, 0, 8, 8);
        assert_ne!(rax, eax);
        assert_ne!(eax, ah);
        assert!(rax.same_register(&ah));
        assert_eq!(rax.full(), ah.full());
    }

    #[test]
    fn the_set_tracks_full_registers_and_never_aliases() {
        let mut set = RegisterSet::empty();
        set.insert(RegisterId::slice(1, 0, 8, 8)); // AH
        assert!(set.contains(RegisterId::new(1, 0, 64))); // RAX
        assert!(!set.contains(RegisterId::new(1, 4, 64))); // RSP
        assert_eq!(set.mask_for_class(1), Some(1));

        set.insert(RegisterId::new(2, 64, 512));
        assert!(set.contains(RegisterId::new(2, 64, 512)));
        assert!(
            !set.contains(RegisterId::new(2, 0, 512)),
            "64 must not alias 0"
        );
        assert_eq!(set.mask_for_class(2), None, "an index past 63 has no mask");
        assert_eq!(set.len(), 2);
    }
}
