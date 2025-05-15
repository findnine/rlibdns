use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct PtrRecord {
    dns_class: Option<RRClasses>,
    cache_flush: bool,
    ttl: u32,
    domain: Option<String>
}

impl Default for PtrRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            cache_flush: false,
            ttl: 0,
            domain: None
        }
    }
}

impl RecordBase for PtrRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let dns_class = u16::from_be_bytes([buf[off], buf[off+1]]);
        let cache_flush = (dns_class & 0x8000) != 0;
        let dns_class = Some(RRClasses::from_code(dns_class & 0x7FFF).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (domain, _) = unpack_domain(buf, off+8);

        Self {
            dns_class,
            cache_flush,
            ttl,
            domain: Some(domain)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());

        let mut dns_class = self.dns_class.unwrap().get_code();
        if self.cache_flush {
            dns_class = dns_class | 0x8000;
        }

        buf.splice(2..4, dns_class.to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_domain(self.domain.as_ref().unwrap().as_str(), label_map, off+12));

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Ptr
    }

    fn upcast(self) -> Box<dyn RecordBase> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl PtrRecord {

    pub fn new(dns_classes: RRClasses, cache_flush: bool, ttl: u32, domain: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
            cache_flush,
            ttl,
            domain: Some(domain.to_string())
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

    pub fn set_domain(&mut self, domain: &str) {
        self.domain = Some(domain.to_string());
    }

    pub fn get_domain(&self) -> Option<String> {
        self.domain.clone()
    }
}

impl fmt::Display for PtrRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "type {:?}, class {:?}, domain {}", self.get_type(), self.dns_class.unwrap(), self.domain.as_ref().unwrap())
    }
}
