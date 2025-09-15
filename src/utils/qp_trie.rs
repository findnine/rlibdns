use std::mem;

fn encode_fqdn(name: &str) -> Vec<u8> {
    if name.is_empty() {
        return vec![0x00];
    }

    let mut out = Vec::with_capacity(name.len() + 1);
    for label in name.split('.').rev() {
        let lower = label.to_ascii_lowercase();
        out.extend_from_slice(lower.as_bytes());
        out.push(0x00);
    }
    out
}

fn decode_fqdn(raw: &[u8]) -> String {
    if raw == [0x00] {
        return String::new();
    }

    let mut labels: Vec<&str> = Vec::new();
    let mut start = 0;

    for i in 0..raw.len() {
        if raw[i] == 0 {
            if i > start {
                labels.push(std::str::from_utf8(&raw[start..i]).unwrap());
            }
            start = i + 1;
        }
    }
    labels.reverse();
    labels.join(".")
}

fn nibbles_len(bytes: &[u8]) -> usize {
    bytes.len() * 2
}

fn get_nibble(bytes: &[u8], i: usize) -> u8 {
    let b = bytes[i >> 1];

    if (i & 1) == 0 {
        b >> 4

    } else {
        b & 0x0F
    }
}

fn slice_nibbles(src: &[u8], start: usize, end: usize) -> (Vec<u8>, usize) {
    debug_assert!(end >= start);
    let mut out = Vec::with_capacity(((end - start) + 1) / 2);
    let mut out_len = 0;

    for i in start..end {
        let nib = get_nibble(src, i);

        if (out_len & 1) == 0 {
            out.push(nib << 4);

        } else {
            let last = out.last_mut().unwrap();
            *last |= nib;
        }

        out_len += 1;
    }
    (out, out_len)
}

fn common_prefix_len(node_pref: &[u8], node_pref_len: usize, key: &[u8], key_off: usize, key_len: usize) -> usize {
    let max = node_pref_len.min(key_len - key_off);
    let mut i = 0usize;
    while i < max {
        if get_nibble(node_pref, i) != get_nibble(key, key_off + i) {
            break;
        }
        i += 1;
    }
    i
}

#[derive(Debug, Clone)]
pub struct QpTrie<V> {
    root: Node<V>
}

#[derive(Debug, Clone)]
struct Node<V> {
    prefix: Vec<u8>,
    prefix_len: usize,
    value: Option<V>,
    bitmap: u16,
    children: Vec<Box<Node<V>>>
}

impl<V> Default for QpTrie<V> {

    fn default() -> Self {
        Self {
            root: Node {
                prefix: Vec::new(),
                prefix_len: 0,
                value: None,
                bitmap: 0,
                children: Vec::new()
            }
        }
    }
}

impl<V> QpTrie<V> {

    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_raw(&mut self, key: Vec<u8>, val: V) -> Option<V> {
        let key_len = nibbles_len(&key);
        insert_at(&mut self.root, &key, 0, key_len, val)
    }

    pub fn get_raw(&self, key: &[u8]) -> Option<&V> {
        let key_len = nibbles_len(key);
        get_exact_at(&self.root, key, 0, key_len)
    }

    pub fn get_raw_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        let key_len = nibbles_len(key);
        get_exact_at_mut(&mut self.root, key, 0, key_len)
    }

    pub fn get_longest_prefix_raw(&self, key: &[u8]) -> Option<&V> {
        let key_len = nibbles_len(key);
        get_longest_at(&self.root, key, 0, key_len, None)
    }

    pub fn insert_fqdn(&mut self, name: &str, val: V) -> Option<V> {
        self.insert_raw(encode_fqdn(name), val)
    }

    pub fn get_fqdn(&self, name: &str) -> Option<&V> {
        self.get_raw(&encode_fqdn(name))
    }

    pub fn get_fqdn_mut(&mut self, name: &str) -> Option<&mut V> {
        self.get_raw_mut(&encode_fqdn(name))
    }

    pub fn get_deepest_suffix(&self, qname: &str) -> Option<&V> {
        self.get_longest_prefix_raw(&encode_fqdn(qname))
    }

    pub fn get_deepest_suffix_with_name(&self, qname: &str) -> Option<(String, &V)> {
        let raw = encode_fqdn(qname);
        let key_len = nibbles_len(&raw);
        let best = get_longest_at2(&self.root, &raw, 0, key_len, None)?;
        let (_v, matched_nibbles) = best;

        let (matched_raw, _len) = slice_nibbles(&raw, 0, matched_nibbles);
        let apex = decode_fqdn(&matched_raw);
        Some((apex, best.0))
    }
}

fn bit_is_set(bm: u16, nib: u8) -> bool {
    (bm >> nib) & 1 == 1
}

fn rank(bm: u16, nib: u8) -> usize {
    let mask = if nib == 0 {
        0
    } else {
        (1u16 << nib) - 1
    };
    (bm & mask).count_ones() as usize
}

impl<V> Node<V> {

    fn child_index(&self, nib: u8) -> Option<usize> {
        if bit_is_set(self.bitmap, nib) {
            return Some(rank(self.bitmap, nib));
        }
        
        None
    }

    fn attach_child(&mut self, nib: u8, child: Box<Node<V>>) {
        let idx = rank(self.bitmap, nib);
        self.bitmap |= 1u16 << nib;
        self.children.insert(idx, child);
    }
}

fn insert_at<V>(node: &mut Node<V>, key: &[u8], mut off: usize, key_len: usize, mut val: V) -> Option<V> {
    let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
    if lcp < node.prefix_len {
        let branch_nib_old = get_nibble(&node.prefix, lcp);
        let (old_suffix_bytes, old_suffix_len) = slice_nibbles(&node.prefix, lcp + 1, node.prefix_len);

        let old_value = node.value.take();
        let old_bitmap = node.bitmap;
        let old_children = mem::take(&mut node.children);
        let old_child = Box::new(Node {
            prefix: old_suffix_bytes,
            prefix_len: old_suffix_len,
            value: old_value,
            bitmap: old_bitmap,
            children: old_children,
        });

        let (new_pref_bytes, _new_len) = slice_nibbles(&node.prefix, 0, lcp);
        node.prefix = new_pref_bytes;
        node.prefix_len = lcp;
        node.bitmap = 0;
        node.children = Vec::new();

        node.attach_child(branch_nib_old, old_child);
    }

    off += common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);

    if off == key_len {
        return mem::replace(&mut node.value, Some(val));
    }

    let nib = get_nibble(key, off);
    if let Some(idx) = node.child_index(nib) {
        return insert_at(&mut node.children[idx], key, off + 1, key_len, val);
    }

    let (leaf_pref_bytes, leaf_pref_len) = slice_nibbles(key, off + 1, key_len);
    let leaf = Box::new(Node {
        prefix: leaf_pref_bytes,
        prefix_len: leaf_pref_len,
        value: Some(val),
        bitmap: 0,
        children: Vec::new(),
    });
    node.attach_child(nib, leaf);
    None
}

fn get_exact_at<'a, V>(
    node: &'a Node<V>,
    key: &[u8],
    mut off: usize,
    key_len: usize
) -> Option<&'a V> {
    let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
    if lcp < node.prefix_len {
        return None;
    }
    off += lcp;

    if off == key_len {
        return node.value.as_ref();
    }

    let nib = get_nibble(key, off);
    if let Some(idx) = node.child_index(nib) {
        return get_exact_at(&node.children[idx], key, off + 1, key_len);
    }

    None
}

fn get_exact_at_mut<'a, V>(node: &'a mut Node<V>, key: &[u8], mut off: usize, key_len: usize) -> Option<&'a mut V> {
    let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
    if lcp < node.prefix_len {
        return None;
    }
    off += lcp;

    if off == key_len {
        return node.value.as_mut();
    }
    let nib = get_nibble(key, off);
    if let Some(idx) = node.child_index(nib) {
        return get_exact_at_mut(&mut node.children[idx], key, off + 1, key_len);
    }

    None
}

fn get_longest_at<'a, V>(node: &'a Node<V>, key: &[u8], mut off: usize, key_len: usize, mut best: Option<&'a V>) -> Option<&'a V> {
    let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
    if lcp < node.prefix_len {
        return best;
    }

    off += lcp;
    if let Some(v) = node.value.as_ref() {
        best = Some(v);
    }

    if off == key_len {
        return best;
    }

    let nib = get_nibble(key, off);
    if let Some(idx) = node.child_index(nib) {
        return get_longest_at(&node.children[idx], key, off + 1, key_len, best);
    }

    best
}

fn get_longest_at2<'a, V>(node: &'a Node<V>, key: &[u8], mut off: usize, key_len: usize, best: Option<(&'a V, usize)>) -> Option<(&'a V, usize)> {
    let lcp = common_prefix_len(&node.prefix, node.prefix_len, key, off, key_len);
    if lcp < node.prefix_len {
        return best;
    }
    off += lcp;

    let mut best = best;
    if let Some(v) = node.value.as_ref() {
        best = Some((v, off));
    }

    if off == key_len {
        return best;
    }

    let nib = get_nibble(key, off);
    if let Some(idx) = node.child_index(nib) {
        return get_longest_at2(&node.children[idx], key, off + 1, key_len, best);
    }

    best
}
