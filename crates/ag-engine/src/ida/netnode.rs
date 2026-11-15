//! The netnode layer: the index's keys read as nodes and their values.
//!
//! IDA stores everything in netnodes. A node is named by a key `N<name>`
//! whose value is its id, or addressed directly by its id — an effective
//! address for the node that holds one address's comments and types. A
//! node's data hangs off keys `.<id><tag><index>`: `S` a supval (a string
//! or blob), `A` an altval (a number), `C` a charval, `H` a hashval, and
//! `V` the node's own value. Indices are big-endian in the key and read
//! signed, so an altval at `-1` is the root's version.

use std::collections::BTreeMap;

use super::container::Database;

/// One netnode: its name and its tagged values.
#[derive(Debug, Clone, Default)]
pub struct Node {
    /// The name a `N` key gives the node, when it has one.
    pub name: Option<String>,
    /// Supvals (`S`), by signed index: comments, types, strings.
    pub sup: BTreeMap<i64, Vec<u8>>,
    /// Altvals (`A`), by signed index: numbers.
    pub alt: BTreeMap<i64, Vec<u8>>,
    /// Charvals (`C`), by signed index.
    pub char: BTreeMap<i64, Vec<u8>>,
    /// Hashvals (`H`), by signed index.
    pub hash: BTreeMap<i64, Vec<u8>>,
    /// The `R` tag: repeatable function comments on the `$ funcs` node.
    pub r: BTreeMap<i64, Vec<u8>>,
    /// The node's own value (`V`): a string or a blob.
    pub value: Option<Vec<u8>>,
}

impl Node {
    /// The supval at `index` as a string, without its trailing NUL.
    pub fn supstr(&self, index: i64) -> Option<String> {
        self.sup.get(&index).map(|bytes| string_of(bytes))
    }

    /// The altval at `index` as a signed integer, read by its width.
    pub fn altval(&self, index: i64) -> Option<i64> {
        self.alt.get(&index).map(|bytes| int_of(bytes))
    }
}

/// The nodes of a database, by id and by name.
#[derive(Debug, Clone)]
pub struct Netnodes {
    wordsize: usize,
    nodes: BTreeMap<u64, Node>,
    by_name: BTreeMap<String, u64>,
}

/// The first node id that is a name, not an address: ids below it are
/// effective addresses.
pub fn nodebase(wordsize: usize) -> u64 {
    if wordsize == 4 {
        0xFF00_0000
    } else {
        0xFF00_0000_0000_0000
    }
}

impl Netnodes {
    /// Read every netnode out of the database index.
    pub fn read(db: &Database) -> Netnodes {
        let wordsize = db.wordsize;
        let mut nodes: BTreeMap<u64, Node> = BTreeMap::new();
        let mut by_name: BTreeMap<String, u64> = BTreeMap::new();
        for (key, value) in &db.index {
            match key.first() {
                Some(b'N') => {
                    let name = string_of(&key[1..]);
                    // A name's value is the node id, little-endian.
                    let id = uint_le(value, wordsize);
                    by_name.insert(name.clone(), id);
                    nodes.entry(id).or_default().name = Some(name);
                }
                Some(b'.') => {
                    if key.len() < 1 + wordsize + 1 {
                        continue;
                    }
                    let id = uint_of(&key[1..1 + wordsize], wordsize);
                    let tag = key[1 + wordsize];
                    let rest = &key[1 + wordsize + 1..];
                    let node = nodes.entry(id).or_default();
                    match tag {
                        b'V' => node.value = Some(value.clone()),
                        b'S' | b'A' | b'C' | b'H' | b'R' => {
                            if rest.len() < wordsize {
                                continue;
                            }
                            let index = signed_be(&rest[..wordsize], wordsize);
                            let map = match tag {
                                b'S' => &mut node.sup,
                                b'A' => &mut node.alt,
                                b'C' => &mut node.char,
                                b'R' => &mut node.r,
                                _ => &mut node.hash,
                            };
                            map.insert(index, value.clone());
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        Netnodes {
            wordsize,
            nodes,
            by_name,
        }
    }

    /// The node at `id`, when it exists.
    pub fn node(&self, id: u64) -> Option<&Node> {
        self.nodes.get(&id)
    }

    /// The node a name names, when it exists.
    pub fn by_name(&self, name: &str) -> Option<&Node> {
        self.by_name.get(name).and_then(|id| self.nodes.get(id))
    }

    /// The id a name names, when it exists.
    pub fn id_of(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    /// Every node, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &Node)> {
        self.nodes.iter().map(|(id, node)| (*id, node))
    }

    /// The ids that are effective addresses (below the nodebase), in order.
    pub fn addresses(&self) -> impl Iterator<Item = u64> + '_ {
        let base = nodebase(self.wordsize);
        self.nodes.keys().copied().filter(move |id| *id < base)
    }

    /// The name of the node at `id`, when it has one.
    pub fn name_of(&self, id: u64) -> Option<&str> {
        self.nodes.get(&id).and_then(|node| node.name.as_deref())
    }
}

/// A NUL-terminated string, read as UTF-8 (lossily).
pub fn string_of(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// An unsigned integer of the node width, big-endian as the keys pack it.
fn uint_of(bytes: &[u8], wordsize: usize) -> u64 {
    let mut value = 0u64;
    for &byte in bytes.iter().take(wordsize) {
        value = (value << 8) | u64::from(byte);
    }
    value
}

/// An unsigned integer of the node width, little-endian as a name's value
/// stores the id it names.
fn uint_le(bytes: &[u8], wordsize: usize) -> u64 {
    let mut value = 0u64;
    for (i, &byte) in bytes.iter().take(wordsize).enumerate() {
        value |= u64::from(byte) << (8 * i);
    }
    value
}

/// A signed index of the node width, big-endian as the keys pack it and
/// sign-extended: an altval at `-1` is keyed by `0xFFFFFFFF`.
fn signed_be(bytes: &[u8], wordsize: usize) -> i64 {
    let value = uint_of(bytes, wordsize);
    if wordsize == 4 {
        i64::from(value as u32 as i32)
    } else {
        value as i64
    }
}

/// A signed integer, read little-endian by its width as altvals are stored.
pub fn int_of(bytes: &[u8]) -> i64 {
    match bytes.len() {
        1 => i64::from(bytes[0] as i8),
        2 => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
        4 => i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        8 => i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        _ => 0,
    }
}
