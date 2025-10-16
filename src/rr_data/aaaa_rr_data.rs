use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv6Addr;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AaaaRRData {
    address: Option<Ipv6Addr>
}

impl Default for AaaaRRData {

    fn default() -> Self {
        Self {
            address: None
        }
    }
}

impl RRData for AaaaRRData {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let address = match length {
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[off + 2..off + 2 + length]);
                Ipv6Addr::from(octets)
            }
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
        let mut buf = Vec::with_capacity(18);

        unsafe { buf.set_len(2); };

        buf.extend_from_slice(&self.address.ok_or_else(|| RRDataError("address param was not set".to_string()))?.octets());

        let length = (buf.len()-2) as u16;
        buf[0..2].copy_from_slice(&length.to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Aaaa
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

impl AaaaRRData {

    pub fn new(address: Ipv6Addr) -> Self {
        Self {
            address: Some(address)
        }
    }

    pub fn set_address(&mut self, address: Ipv6Addr) {
        self.address = Some(address);
    }

    pub fn get_address(&self) -> Option<Ipv6Addr> {
        self.address
    }
}

impl ZoneRRData for AaaaRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.address = Some(value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse address param for record type {}", self.get_type())))?),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for AaaaRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{}", self.get_type().to_string(),
               self.address.map(|a| a.to_string()).unwrap_or_default())
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 ];
    let record = AaaaRRData::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
