use crate::node::{Branch, Leaf, Node};

#[derive(Clone, Debug)]
pub struct Trie<V> {
    root: Option<Node<Vec<u8>, V>>
}

impl<V> Default for Trie<V> {

    fn default() -> Self {
        Self {
            root: None
        }
    }
}

impl<V> Trie<V> {

    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn nibble(key: &[u8], i: usize) -> usize {
        if i / 2 >= key.len() {
            return 0;
        }

        let b = key[i / 2];
        1 + if (i & 1) == 0 { (b >> 4) as usize } else { (b & 0x0F) as usize }
    }

    fn first_diff_nibble(a: &[u8], b: &[u8]) -> usize {
        let max_nibbles = 2 * a.len().max(b.len()) + 1; // +1 for COMPLETE
        for i in 0..max_nibbles {
            if Self::nibble(a, i) != Self::nibble(b, i) {
                return i;
            }
        }
        0
    }

    pub fn insert(&mut self, key: Vec<u8>, val: V) -> Option<V> {
        Self::insert_at(&mut self.root, key, val)
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        let mut cur = self.root.as_ref()?;
        let key = key;
        loop {
            match cur {
                Node::Leaf(leaf) => {
                    return if leaf.key.as_slice() == key {
                        Some(&leaf.val)
                    } else {
                        None
                    };
                }
                Node::Branch(br) => {
                    let n = Self::nibble(key, br.offset);
                    cur = br.get_child(n)?;
                }
            }
        }
    }

    pub fn get_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        let mut cur = self.root.as_mut()?;
        loop {
            match cur {
                Node::Leaf(leaf) => {
                    return if leaf.key.as_slice() == key {
                        Some(&mut leaf.val)
                    } else {
                        None
                    };
                }
                Node::Branch(br) => {
                    let n = Self::nibble(key, br.offset);
                    cur = br.get_child_mut(n)?;
                }
            }
        }
    }

    pub fn get_deepest(&self, query: &[u8]) -> Option<(&[u8], &V)> {
        let mut node = self.root.as_ref()?;
        let mut best: Option<(&[u8], &V)> = None;

        loop {
            match node {
                Node::Branch(br) => {
                    // If there is a COMPLETE child (nibble 0), that child is a key that ends
                    // before or at this offset; it’s a prefix of any path that reaches here.
                    if br.has_child(0) {
                        if let Some(Node::Leaf(leaf)) = br.get_child(0) {
                            if is_prefix(leaf.key.as_slice(), query) {
                                best = Some((leaf.key.as_slice(), &leaf.val));
                            }
                        }
                    }

                    // Descend along the nibble of the query at this offset.
                    let n = Self::nibble(query, br.offset);
                    match br.get_child(n) {
                        Some(child) => node = child,
                        None => return best, // can't go further; return last prefix seen
                    }
                }
                Node::Leaf(leaf) => {
                    // If we land on a leaf, it’s either an exact match or not a prefix.
                    if is_prefix(leaf.key.as_slice(), query) {
                        return Some((leaf.key.as_slice(), &leaf.val));
                    }
                    return best;
                }
            }
        }
    }

    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    fn insert_at(slot: &mut Option<Node<Vec<u8>, V>>, key: Vec<u8>, val: V) -> Option<V> {
        match slot {
            None => {
                *slot = Some(Node::Leaf(Leaf::new(key, val)));
                None
            }
            Some(node) => {
                match node {
                    Node::Leaf(leaf) => {
                        if leaf.key.as_slice() == key.as_slice() {
                            // Exact key: replace value.
                            return Some(std::mem::replace(&mut leaf.val, val));
                        }

                        // Split at first differing nibble.
                        let split = Self::first_diff_nibble(&leaf.key, &key);

                        // Take existing leaf out, replace with a new branch at `split`.
                        let old_leaf = match std::mem::replace(node, Node::Branch(Branch::new(split))) {
                            Node::Leaf(l) => l,
                            _ => unreachable!(),
                        };

                        if let Node::Branch(br) = node {
                            // Old leaf under its nibble.
                            let old_n = Self::nibble(&old_leaf.key, split);
                            br.insert_child(old_n, Node::Leaf(old_leaf));

                            // New leaf under its nibble.
                            let new_n = Self::nibble(&key, split);
                            br.insert_child(new_n, Node::Leaf(Leaf::new(key, val)));
                            None
                        } else {
                            unreachable!()
                        }
                    }
                    Node::Branch(br) => {
                        let n = Self::nibble(&key, br.offset);
                        if let Some(child) = br.get_child_mut(n) {
                            // Recurse by temporarily taking ownership.
                            let mut tmp = Some(std::mem::replace(child, Node::Branch(Branch::default())));
                            let ret = Self::insert_at(&mut tmp, key, val);
                            *child = tmp.unwrap();
                            ret
                        } else {
                            // Create a new leaf at nibble `n`.
                            br.insert_child(n, Node::Leaf(Leaf::new(key, val)));
                            None
                        }
                    }
                }
            }
        }
    }
}

fn is_prefix(a: &[u8], b: &[u8]) -> bool {
    b.len() >= a.len() && &b[..a.len()] == a
}
