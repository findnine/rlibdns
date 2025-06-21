use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::{pack_domain, unpack_domain};
use crate::utils::ordered_map::OrderedMap;

#[derive(Clone, Debug)]
pub struct HttpsRecord {
    class: RRClasses,
    ttl: u32,
    priority: u16,
    target: Option<String>,
    params: OrderedMap<u16, Vec<u8>>
}

impl Default for HttpsRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            priority: 0,
            target: None,
            params: OrderedMap::new()
        }
    }
}

impl RecordBase for HttpsRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let priority = u16::from_be_bytes([buf[off+8], buf[off+9]]);

        let (target, length) = unpack_domain(&buf, off+10);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += length+10;

        let mut params = OrderedMap::new();
        while off < data_length {
            let key = u16::from_be_bytes([buf[off], buf[off+1]]);
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            params.insert(key, buf[off + 4..off + 4 + length].to_vec());
            off += length+4;
        }

        Self {
            class,
            ttl,
            priority,
            target: Some(target),
            params
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 12];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.class.get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.splice(10..12, self.priority.to_be_bytes());

        buf.extend_from_slice(&pack_domain(self.target.as_ref().unwrap().as_str(), label_map, off+12, true));

        for (key, value) in self.params.iter() {
            buf.extend_from_slice(&key.to_be_bytes());
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(&value);
        }

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Https
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

    fn clone_box(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }
}

impl HttpsRecord {

    pub fn new(ttl: u32, class: RRClasses) -> Self {
        Self {
            class,
            ttl,
            ..Self::default()
        }
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }
}

impl fmt::Display for HttpsRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.priority,
               format!("{}.", self.target.as_ref().unwrap()))
               //self.address.as_ref().unwrap())
        //write!(f, "type {:?}, class {:?}", self.get_type(), self.class)
    }
}
