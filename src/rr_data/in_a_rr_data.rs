use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv4Addr;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InARRData {
    address: Option<Ipv4Addr>
}

impl Default for InARRData {

    fn default() -> Self {
        Self {
            address: None
        }
    }
}

impl RRData for InARRData {

    fn from_bytes(buf: &[u8], off: usize, len: usize) -> Result<Self, RRDataError> {
        let address = match len {
            4 => Ipv4Addr::new(buf[off], buf[off+1], buf[off+2], buf[off+3]),
            _ => return Err(RRDataError("invalid inet address".to_string()))
        };

        Ok(Self {
            address: Some(address)
        })
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(4);

        buf.extend_from_slice(&self.address.ok_or_else(|| RRDataError("address param was not set".to_string()))?.octets());

        Ok(buf)
    }

    fn upcast(self) -> Box<dyn RRData> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RRData> {
        Box::new(self.clone())
    }

    fn eq_box(&self, other: &dyn RRData) -> bool {
        other.as_any().downcast_ref::<Self>().map_or(false, |o| self == o)
    }
}

impl InARRData {

    pub fn new(address: Ipv4Addr) -> Self {
        Self {
            address: Some(address)
        }
    }

    pub fn set_address(&mut self, address: Ipv4Addr) {
        self.address = Some(address);
    }

    pub fn get_address(&self) -> Option<Ipv4Addr> {
        self.address
    }
}

impl ZoneRRData for InARRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.address = Some(value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse address param for record type A"))?),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type A"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for InARRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address.map(|a| a.to_string()).unwrap_or_default())
    }
}

#[test]
fn test() {
    let buf = vec![ 0x7f, 0x0, 0x0, 0x1 ];
    let record = InARRData::from_bytes(&buf, 0, buf.len()).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
