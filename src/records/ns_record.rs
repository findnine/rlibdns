use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::{pack_domain, unpack_domain};

#[derive(Clone)]
pub struct NsRecord {
    dns_class: Option<RRClasses>,
    ttl: u32,
    server: Option<String>
}

impl Default for NsRecord {

    fn default() -> Self {
        Self {
            dns_class: None,
            ttl: 0,
            server: None
        }
    }
}

impl RecordBase for NsRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let dns_class = Some(RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap());
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (server, _) = unpack_domain(buf, off+8);

        Self {
            dns_class,
            ttl,
            server: Some(server)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.dns_class.unwrap().get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_domain(self.server.as_ref().unwrap().as_str(), label_map, off+12));

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Ns
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

impl NsRecord {

    pub fn new(dns_classes: RRClasses, ttl: u32, server: &str) -> Self {
        Self {
            dns_class: Some(dns_classes),
            ttl,
            server: Some(server.to_string())
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

    pub fn set_server(&mut self, server: &str) {
        self.server = Some(server.to_string());
    }

    pub fn get_server(&self) -> Option<String> {
        self.server.clone()
    }
}

impl fmt::Display for NsRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "type {:?}, class {:?}, server {}", self.get_type(), self.dns_class.unwrap(), self.server.as_ref().unwrap())
    }
}
