//! Shared back/forward navigation history.

/// A bounded back/forward history over a value.
#[derive(Debug, Clone, Default)]
pub struct History<T> {
    entries: Vec<T>,
    cursor: Option<usize>,
    capacity: usize,
}

impl<T: Clone + PartialEq> History<T> {
    /// A history holding at most `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            cursor: None,
            capacity: capacity.max(1),
        }
    }

    /// Push a new entry, discarding any forward entries.
    pub fn push(&mut self, entry: T) {
        if self.cursor.map(|c| self.entries.get(c) == Some(&entry)) == Some(true) {
            return;
        }

        if let Some(cursor) = self.cursor {
            self.entries.truncate(cursor + 1);
        }

        self.entries.push(entry);

        if self.entries.len() > self.capacity {
            let overflow = self.entries.len() - self.capacity;
            self.entries.drain(0..overflow);
        }

        self.cursor = Some(self.entries.len() - 1);
    }

    /// Step back one entry.
    pub fn back(&mut self) -> Option<&T> {
        let cursor = self.cursor?;
        if cursor == 0 {
            return None;
        }
        self.cursor = Some(cursor - 1);
        self.entries.get(self.cursor?)
    }

    /// Step forward one entry.
    pub fn forward(&mut self) -> Option<&T> {
        let cursor = self.cursor?;
        let next = cursor + 1;
        if next >= self.entries.len() {
            return None;
        }
        self.cursor = Some(next);
        self.entries.get(self.cursor?)
    }

    /// Whether a backward step is available.
    pub fn can_go_back(&self) -> bool {
        self.cursor.is_some_and(|c| c > 0)
    }

    /// Whether a forward step is available.
    pub fn can_go_forward(&self) -> bool {
        self.cursor.is_some_and(|c| c + 1 < self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_drops_the_forward_entries() {
        let mut history = History::new(8);
        history.push("a");
        history.push("b");
        history.push("c");
        assert_eq!(history.back(), Some(&"b"));
        history.push("d");
        assert!(!history.can_go_forward());
        assert_eq!(history.back(), Some(&"b"));
        assert_eq!(history.forward(), Some(&"d"));
    }

    #[test]
    fn the_same_entry_is_not_pushed_twice() {
        let mut history = History::new(8);
        history.push(1);
        history.push(1);
        assert!(!history.can_go_back());
    }

    #[test]
    fn the_oldest_entry_falls_off_at_capacity() {
        let mut history = History::new(2);
        history.push("a");
        history.push("b");
        history.push("c");
        assert_eq!(history.back(), Some(&"b"));
        assert!(history.back().is_none());
    }
}
