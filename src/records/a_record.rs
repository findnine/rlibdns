use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv4Addr;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};

#[derive(Clone, Debug)]
pub struct ARecord {
    pub(crate) address: Option<Ipv4Addr>
}

impl Default for ARecord {

    fn default() -> Self {
        Self {
            address: None
        }
    }
}

impl RecordBase for ARecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;

        let address = match length {
            4 => Ipv4Addr::new(buf[off+2], buf[off+3], buf[off+4], buf[off+5]),
            _ => return Err(RecordError("invalid inet address".to_string()))
        };

        Ok(Self {
            address: Some(address)
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 6];

        buf.splice(2..6, self.address.as_ref().unwrap().octets().to_vec());

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

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

    fn clone_box(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }
}

impl ARecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
        }
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
        write!(f, "{:<8}{}", self.get_type().to_string(),
               self.address.as_ref().unwrap())
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x4, 0x7f, 0x0, 0x0, 0x1 ];
    let record = ARecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
