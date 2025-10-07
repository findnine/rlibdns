use std::collections::HashMap;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NameError {
    Empty,
    LabelTooLong,
    NameTooLong,
    BadDot
}

#[derive(Debug, Clone)]
pub struct NameList {
    names: Vec<Box<str>>,
    // hash -> one or more ids (rare collisions)
    buckets: HashMap<u64, Vec<u32>>,
}

impl Default for NameList {
    fn default() -> Self {
        Self {
            names: Vec::new(),
            buckets: HashMap::new()
        }
    }
}

impl NameList {

    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern(&mut self, name: &str) -> Result<u32, NameError> {
        let canon = canonicalize_name(name)?;
        let h = fnv1a64(&canon);
        if let Some(v) = self.buckets.get(&h) {
            for &id in v {
                if &*self.names[id as usize] == canon.as_str() {
                    return Ok(id);
                }
            }
        }

        let id = self.names.len() as u32;
        self.names.push(canon.into_boxed_str());
        self.buckets.entry(h).or_default().push(id);
        Ok(id)
    }

    pub fn try_get_id(&self, name: &str) -> Option<u32> {
        let Ok(canon) = canonicalize_name_no_alloc(name) else { return None; };
        let h = fnv1a64(&canon);
        self.buckets.get(&h).and_then(|v| {
            v.iter().copied().find(|id| &*self.names[*id as usize] == canon.as_str())
        })
    }

    pub fn get(&self, id: u32) -> &str {
        &self.names[id as usize]
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }
}

fn canonicalize_name(input: &str) -> Result<String, NameError> {
    let s = input.trim();
    if s.is_empty() { return Err(NameError::Empty); }

    // Disallow leading dot and ".."
    if s.starts_with('.') {
        return Err(NameError::BadDot);
    }
    
    if s.contains("..") {
        return Err(NameError::BadDot);
    }

    // Add trailing dot if missing.
    let need_dot = !s.ends_with('.');
    let est_len = s.len() + if need_dot { 1 } else { 0 };

    if est_len > 255 {
        return Err(NameError::NameTooLong);
    }

    // Lowercase ASCII in-place into a new String. (DNS names are case-insensitive; keep ASCII.)
    let mut out = String::with_capacity(est_len);
    for b in s.bytes() {
        out.push(match b {
            b'A'..=b'Z' => (b + 32) as char,
            _ => b as char,
        });
    }
    if need_dot { out.push('.'); }

    // Validate labels (<=63)
    let mut last = 0usize;
    for (i, ch) in out.char_indices() {
        if ch == '.' {
            if i == last { return Err(NameError::BadDot); } // empty label
            if i - last > 63 { return Err(NameError::LabelTooLong); }
            last = i + 1;
        }
    }
    // ending '.' guarantees the last label checked

    Ok(out)
}

fn canonicalize_name_no_alloc(input: &str) -> Result<String, NameError> {
    canonicalize_name(input)
}

fn fnv1a64(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x00000100000001B3);
    }
    h
}

#[test]
fn test() {
    let mut store = NameList::new();
    store.intern("hello.com");
    let v = store.intern("test.com").unwrap();

    println!("{}", store.get(v));
}
