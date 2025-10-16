use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, pack_fqdn_compressed, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NsRRData {
    server: Option<String>
}

impl Default for NsRRData {

    fn default() -> Self {
        Self {
            server: None
        }
    }
}

impl RRData for NsRRData {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]);
        if length == 0 {
            return Ok(Default::default());
        }

        let (server, _) = unpack_fqdn(buf, off+2);

        Ok(Self {
            server: Some(server)
        })
    }

    fn to_wire(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(34);

        unsafe { buf.set_len(2); };

        buf.extend_from_slice(&pack_fqdn_compressed(self.server.as_ref()
            .ok_or_else(|| RRDataError("server param was not set".to_string()))?, compression_data, off+2));

        let length = (buf.len()-2) as u16;
        buf[0..2].copy_from_slice(&length.to_be_bytes());

        Ok(buf)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(34);

        unsafe { buf.set_len(2); };

        buf.extend_from_slice(&pack_fqdn(self.server.as_ref()
            .ok_or_else(|| RRDataError("server param was not set".to_string()))?));

        let length = (buf.len()-2) as u16;
        buf[0..2].copy_from_slice(&length.to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Ns
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

impl NsRRData {

    pub fn new(server: &str) -> Self {
        Self {
            server: Some(server.to_string())
        }
    }

    pub fn set_server(&mut self, server: &str) {
        self.server = Some(server.to_string());
    }

    pub fn get_server(&self) -> Option<&String> {
        self.server.as_ref()
    }
}

impl ZoneRRData for NsRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.server = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, &format!("server param is not fully qualified (missing trailing dot) for record type {}", self.get_type())))?.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for NsRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{}", self.get_type().to_string(),
               format!("{}.", self.server.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0xf, 0x3, 0x6e, 0x73, 0x32, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0 ];
    let record = NsRRData::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
