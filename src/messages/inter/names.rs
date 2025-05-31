use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Names {
    Root,
    Domain(String),
}

impl Names {

    pub fn from_wire(buf: &[u8], off: &mut usize) -> Self {
        if buf[*off] == 0 {
            *off += 1;
            Self::Root
        } else {
            let (name, len) = unpack_domain(buf, *off);
            *off += len;
            Self::Domain(name)
        }
    }

    pub fn to_wire(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Vec<u8> {
        match self {
            Self::Root => vec![0],
            Self::Domain(name) => pack_domain(name, label_map, off)
        }
    }

    pub fn from_str(name: &str) -> Self {
        match name {
            "." => Self::Root,
            name => {
                match name.strip_suffix('.') {
                    Some(base) => Self::Domain(base.to_string()),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }
            }
        }
    }
}

impl fmt::Display for Names {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => write!(f, "."),
            Self::Domain(name) => write!(f, "{}", name.clone()),
        }
    }
}
