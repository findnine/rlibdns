use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Debug, Clone)]
pub struct DnsQuery {
    name: String,
    _type: RRTypes,
    class: RRClasses
}

impl DnsQuery {

    pub fn new(name: &str, _type: RRTypes, class: RRClasses) -> Self {
        Self {
            name: name.to_string(),
            _type,
            class
        }
    }

    pub fn from_bytes(buf: &[u8], off: &mut usize) -> Self {
        let (name, len) = unpack_domain(buf, *off);
        *off += len;
        
        let _type = RRTypes::from_code(u16::from_be_bytes([buf[*off], buf[*off+1]])).unwrap();
        let class = RRClasses::from_code(u16::from_be_bytes([buf[*off+2], buf[*off+3]])).unwrap();
        *off += 4;

        Self {
            name,
            _type,
            class
        }
    }

    pub fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Vec<u8> {
        let mut buf = pack_domain(&self.name, label_map, off);

        buf.extend_from_slice(&self._type.get_code().to_be_bytes());
        buf.extend_from_slice(&self.class.get_code().to_be_bytes());

        buf
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn set_type(&mut self, _type: RRTypes) {
        self._type = _type;
    }

    pub fn get_type(&self) -> RRTypes {
        self._type
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }
}

impl fmt::Display for DnsQuery {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.\t\t\t\t{}\t\t{}", self.name, self.class, self._type)
    }
}
