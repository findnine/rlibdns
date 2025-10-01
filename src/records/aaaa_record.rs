use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv6Addr;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};

#[derive(Clone, Debug)]
pub struct AaaaRecord {
    pub(crate) address: Option<Ipv6Addr>
}

impl Default for AaaaRecord {

    fn default() -> Self {
        Self {
            address: None
        }
    }
}

impl RecordBase for AaaaRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;

        let address = match length {
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[off + 2..off + 2 + length]);
                Ipv6Addr::from(octets)
            }
            _ => return Err(RecordError("invalid inet address".to_string()))
        };

        Ok(Self {
            address: Some(address)
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 18];

        buf.splice(2..18, self.address.ok_or_else(|| RecordError("address param was not set".to_string()))?.octets().to_vec());

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Aaaa
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

impl AaaaRecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
        }
    }

    pub fn set_address(&mut self, address: Ipv6Addr) {
        self.address = Some(address);
    }

    pub fn get_address(&self) -> Option<Ipv6Addr> {
        self.address
    }
}

impl fmt::Display for AaaaRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{}", self.get_type().to_string(),
               self.address.as_ref().unwrap())
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 ];
    let record = AaaaRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
