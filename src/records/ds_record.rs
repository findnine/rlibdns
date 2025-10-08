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
pub struct DsRecord {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>
}

impl Default for DsRecord {

    fn default() -> Self {
        Self {
            key_tag: 0,
            algorithm: 0,
            digest_type: 0,
            digest: Vec::new()
        }
    }
}

impl RecordBase for DsRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let key_tag = 0;
        let algorithm = 0;
        let digest_type = 0;
        let digest = Vec::new();

        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 2];

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Ds
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

impl DsRecord {

    pub fn new(key_tag: u16, algorithm: u8, digest_type: u8, digest: Vec<u8>) -> Self {
        Self {
            key_tag,
            algorithm,
            digest_type,
            digest
        }
    }
}

impl ZoneRecord for DsRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.key_tag = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse key_tag param for record type {}", self.get_type())))?,
            1 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse algorithm param for record type {}", self.get_type())))?,
            2 => self.digest_type = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse digest_type param for record type {}", self.get_type())))?,
            3 => self.digest = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse digest param for record type {}", self.get_type())))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for DsRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {} {}", self.get_type().to_string(),
               self.key_tag,
               self.algorithm,
               self.digest_type,
               hex::encode(&self.digest))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x4, 0x7f, 0x0, 0x0, 0x1 ];
    let record = DsRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
