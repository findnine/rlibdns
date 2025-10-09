use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, pack_fqdn_compressed, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct CNameRRData {
    target: Option<String>
}

impl Default for CNameRRData {

    fn default() -> Self {
        Self {
            target: None
        }
    }
}

impl RRData for CNameRRData {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]);
        if length == 0 {
            return Ok(Default::default());
        }

        let (target, _) = unpack_fqdn(buf, off+2);

        Ok(Self {
            target: Some(target)
        })
    }

    fn to_bytes_compressed(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 2];

        buf.extend_from_slice(&pack_fqdn_compressed(self.target.as_ref()
            .ok_or_else(|| RRDataError("target param was not set".to_string()))?, compression_data, off+2));

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 2];

        buf.extend_from_slice(&pack_fqdn(self.target.as_ref()
            .ok_or_else(|| RRDataError("target param was not set".to_string()))?));

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::CName
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn upcast(self) -> Box<dyn RRData> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn RRData> {
        Box::new(self.clone())
    }
}

impl CNameRRData {

    pub fn new(target: &str) -> Self {
        Self {
            target: Some(target.to_string())
        }
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn get_target(&self) -> Option<&String> {
        self.target.as_ref()
    }
}

impl ZoneRRData for CNameRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.target = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, &format!("network param is not fully qualified (missing trailing dot) for record type {}", self.get_type())))?.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for CNameRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{}", self.get_type().to_string(),
               format!("{}.", self.target.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0xe, 0x2, 0x78, 0x32, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0 ];
    let record = CNameRRData::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
