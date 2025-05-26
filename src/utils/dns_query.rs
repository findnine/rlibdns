use std::collections::HashMap;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Debug, Clone)]
pub struct DnsQuery {
    name: String,
    _type: RRTypes,
    dns_class: RRClasses,
    length: usize
}

impl DnsQuery {

    pub fn new(name: &str, _type: RRTypes, dns_class: RRClasses) -> Self {
        Self {
            name: name.to_string(),
            _type,
            dns_class,
            length: name.len()+6
        }
    }

    pub fn from_bytes(buf: &[u8], off: usize) -> Self {
        let (name, length) = unpack_domain(buf, off);
        let off = off+length;

        let _type = RRTypes::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let dns_class = RRClasses::from_code(u16::from_be_bytes([buf[off+2], buf[off+3]])).unwrap();

        Self {
            name,
            _type,
            dns_class,
            length: length+4
        }
    }

    pub fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Vec<u8> {
        let mut buf = vec![0u8; self.length];

        let address = pack_domain(self.name.as_str(), label_map, off);
        buf[0..address.len()].copy_from_slice(&address);

        let length = address.len();

        buf.splice(length..length+2, self._type.get_code().to_be_bytes());
        buf.splice(length+2..length+4, self.dns_class.get_code().to_be_bytes());

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

    pub fn set_dns_class(&mut self, dns_class: RRClasses) {
        self.dns_class = dns_class;
    }

    pub fn get_dns_class(&self) -> RRClasses {
        self.dns_class
    }

    pub fn get_length(&self) -> usize {
        self.length
    }

    pub fn to_string(&self) -> String {
        format!("[QUERY] {}: type {:?}, class {:?}", self.name, self._type, self.dns_class)
    }
}
