use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::hex;
use crate::zone::inter::zone_record::ZoneRecord;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct NSec3ParamRecord {
    algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>
}

impl Default for NSec3ParamRecord {

    fn default() -> Self {
        Self {
            algorithm: 0,
            flags: 0,
            iterations: 0,
            salt: Vec::new()
        }
    }
}

impl RecordBase for NSec3ParamRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let algorithm = 0;
        let flags = 0;
        let iterations = 0;
        let salt = Vec::new();


        Ok(Self {
            algorithm,
            flags,
            iterations,
            salt
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 4];




        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::NSec3Param
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

impl NSec3ParamRecord {

    pub fn new(algorithm: u8, flags: u8, iterations: u16, salt: Vec<u8>) -> Self {
        Self {
            algorithm,
            flags,
            iterations,
            salt
        }
    }
}

impl ZoneRecord for NSec3ParamRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        match index {
            //0 => self.address = Some(value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse address param for record type {}", self.get_type())))?),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        }

        Ok(())
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for NSec3ParamRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {} {}", self.get_type().to_string(),
               self.algorithm,
               self.flags,
               self.iterations,
               hex::encode(&self.salt))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x5, 0x1, 0x0, 0x0, 0x0, 0x0 ];
    let record = NSec3ParamRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
