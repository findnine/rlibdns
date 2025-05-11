use std::collections::HashMap;
use crate::messages::inter::dns_classes::DnsClasses;
use crate::messages::inter::record_types::RecordTypes;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Debug, Clone)]
pub struct DnsQuery {
    name: String,
    _type: RecordTypes,
    dns_class: DnsClasses,
    length: usize
}

impl DnsQuery {

    pub fn new(name: &str, _type: RecordTypes, dns_class: DnsClasses) -> Self {
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

        let _type = RecordTypes::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let dns_class = DnsClasses::from_code(u16::from_be_bytes([buf[off+2], buf[off+3]])).unwrap();

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

        buf.splice(length..length+2, self.dns_class.get_code().to_be_bytes());
        buf.splice(length+2..length+4, self.dns_class.get_code().to_be_bytes());

        buf
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn set_type(&mut self, _type: RecordTypes) {
        self._type = _type;
    }

    pub fn get_type(&self) -> RecordTypes {
        self._type
    }

    pub fn set_dns_class(&mut self, dns_class: DnsClasses) {
        self.dns_class = dns_class;
    }

    pub fn get_dns_class(&self) -> DnsClasses {
        self.dns_class
    }

    pub fn get_length(&self) -> usize {
        self.length
    }

    pub fn to_string(&self) -> String {
        format!("[QUERY] {}: type {:?}, class {:?}", self.name, self._type, self.dns_class)
    }
}
