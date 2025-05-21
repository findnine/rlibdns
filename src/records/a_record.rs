use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv4Addr;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;

#[derive(Clone)]
pub struct ARecord {
    rr_class: RRClasses,
    cache_flush: bool,
    ttl: u32,
    address: Option<Ipv4Addr>
}

impl Default for ARecord {

    fn default() -> Self {
        Self {
            rr_class: RRClasses::default(),
            cache_flush: false,
            ttl: 0,
            address: None
        }
    }
}

impl RecordBase for ARecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let dns_class = u16::from_be_bytes([buf[off], buf[off+1]]);
        let cache_flush = (dns_class & 0x8000) != 0;
        let rr_class = RRClasses::from_code(dns_class & 0x7FFF).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let length = u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        let record = &buf[off + 8..off + 8 + length];

        let address = match record.len() {
            4 => Ipv4Addr::from(<[u8; 4]>::try_from(record).expect("Invalid IPv4 address")),
            _ => panic!("Invalid Inet Address")
        };

        Self {
            rr_class,
            cache_flush,
            ttl,
            address: Some(address)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());

        let mut rr_class = self.rr_class.get_code();
        if self.cache_flush {
            rr_class = rr_class | 0x8000;
        }

        buf.splice(2..4, rr_class.to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.extend_from_slice(&self.address.unwrap().octets().to_vec());

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::A
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

impl ARecord {

    pub fn new(rr_class: RRClasses, cache_flush: bool, ttl: u32, address: Ipv4Addr) -> Self {
        Self {
            rr_class,
            cache_flush,
            ttl,
            address: Some(address)
        }
    }

    pub fn set_rr_class(&mut self, rr_class: RRClasses) {
        self.rr_class = rr_class;
    }

    pub fn get_rr_class(&self) -> RRClasses {
        self.rr_class
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_address(&mut self, address: Ipv4Addr) {
        self.address = Some(address);
    }

    pub fn get_address(&self) -> Option<Ipv4Addr> {
        self.address
    }
}

impl fmt::Display for ARecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "type {:?}, class {:?}, addr: {}", self.get_type(), self.rr_class, self.address.unwrap())
    }
}
