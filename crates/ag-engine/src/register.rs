use std::collections::BTreeMap;
use std::fmt;

pub type RegisterClass = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegisterId {
    pub class: RegisterClass,
    pub index: u32,
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

#[derive(Clone, Default)]
pub struct RegisterSet {
    masks: BTreeMap<RegisterClass, u64>,
}

impl RegisterSet {
    pub fn empty() -> Self {
        Self {
            masks: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, r: RegisterId) {
        let m = self.masks.entry(r.class).or_insert(0);
        *m |= 1u64 << (r.index & 63);
    }

    pub fn contains(&self, r: RegisterId) -> bool {
        self.masks
            .get(&r.class)
            .is_some_and(|m| m & (1u64 << (r.index & 63)) != 0)
    }

    pub fn mask_for_class(&self, class: RegisterClass) -> Option<u64> {
        self.masks.get(&class).copied()
    }
}

impl fmt::Debug for RegisterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegisterSet{:?}", self.masks)
    }
}
