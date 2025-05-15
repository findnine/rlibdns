use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct CNameRecord {
    dns_class: Option<RRClasses>,
    ttl: u32,
    target: Option<String>
}

impl Default for CNameRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            target: None
        }
    }
}

impl RecordBase for CNameRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let dns_class = Some(RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (target, _) = unpack_domain(buf, off+8);

        Self {
            dns_class,
            ttl,
            target: Some(target)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.dns_class.unwrap().get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_domain(self.target.as_ref().unwrap().as_str(), label_map, off+12));

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Cname
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn upcast(self) -> Box<dyn RecordBase> {
        Box::new(self)
    }
}

impl CNameRecord {

    pub fn new(dns_classes: RRClasses, ttl: u32, target: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            target: Some(target.to_string())
        }
    }

    pub fn set_dns_class(&mut self, dns_class: RRClasses) {
        self.dns_class = Some(dns_class);
    }

    pub fn get_dns_class(&self) -> Option<&RRClasses> {
        self.dns_class.as_ref()
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn get_target(&self) -> Option<String> {
        self.target.clone()
    }
}

impl fmt::Display for CNameRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "type {:?}, class {:?}, target: {}", self.get_type(), self.dns_class.unwrap(), self.target.as_ref().unwrap())
    }
}
