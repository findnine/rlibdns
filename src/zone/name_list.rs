use std::collections::HashMap;

pub struct NameId(pub u32);

pub struct NameList {
    names: HashMap<String, NameId>,
}


/*
use std::collections::HashMap;

// 64-bit FNV-1a (tiny, decent avalanche for short ASCII names)
fn fnv1a64(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x00000100000001B3);
    }
    h
}

pub struct NameListND {
    // id -> name (single owner)
    names: Vec<Box<str>>,
    // hash -> one or more ids (rare collisions)
    buckets: HashMap<u64, Vec<NameId>>,
}

impl Default for NameListND {
    fn default() -> Self {
        Self { names: Vec::new(), buckets: HashMap::new() }
    }
}

impl NameListND {
    pub fn new() -> Self { Self::default() }

    pub fn intern(&mut self, name: &str) -> Result<NameId, NameError> {
        let canon = canonicalize_name(name)?;
        let h = fnv1a64(&canon);
        if let Some(v) = self.buckets.get(&h) {
            // Check collisions
            for &id in v {
                if &*self.names[id.0 as usize] == canon.as_str() {
                    return Ok(id);
                }
            }
        }
        // Not found: insert once
        let id = NameId(self.names.len() as u32);
        self.names.push(canon.into_boxed_str());
        self.buckets.entry(h).or_default().push(id);
        Ok(id)
    }

    pub fn try_get_id(&self, name: &str) -> Option<NameId> {
        let Ok(canon) = canonicalize_name_no_alloc(name) else { return None; };
        let h = fnv1a64(&canon);
        self.buckets.get(&h).and_then(|v| {
            v.iter().copied().find(|id| &*self.names[id.0 as usize] == canon.as_str())
        })
    }

    pub fn get(&self, id: NameId) -> &str {
        &self.names[id.0 as usize]
    }

    pub fn len(&self) -> usize { self.names.len() }
}

*/