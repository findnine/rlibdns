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
pub struct SmimeaRecord {
    usage: u8,
    selector: u8,
    matching_type: u8,
    certificate: Vec<u8>
}

impl Default for SmimeaRecord {

    fn default() -> Self {
        Self {
            usage: 0,
            selector: 0,
            matching_type: 0,
            certificate: Vec::new()
        }
    }
}

impl RecordBase for SmimeaRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let mut length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let usage = buf[off+2];
        let selector = buf[off+3];
        let matching_type = buf[off+4];

        length += off+2;

        let certificate = buf[off+5..length].to_vec();

        Ok(Self {
            usage,
            selector,
            matching_type,
            certificate
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 5];

        buf[2] = self.usage;
        buf[3] = self.selector;
        buf[4] = self.matching_type;

        buf.extend_from_slice(&self.certificate);

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Smimea
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

impl SmimeaRecord {

    pub fn new(usage: u8, selector: u8, matching_type: u8, certificate: Vec<u8>) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            certificate
        }
    }

    pub fn set_usage(&mut self, usage: u8) {
        self.usage = usage;
    }

    pub fn get_usage(&self) -> u8 {
        self.usage
    }

    pub fn set_selector(&mut self, selector: u8) {
        self.selector = selector;
    }

    pub fn get_selector(&self) -> u8 {
        self.selector
    }

    pub fn set_matching_type(&mut self, matching_type: u8) {
        self.matching_type = matching_type;
    }

    pub fn get_matching_type(&self) -> u8 {
        self.matching_type
    }

    pub fn set_certificate(&mut self, certificate: &[u8]) {
        self.certificate = certificate.to_vec();
    }

    pub fn get_certificate(&self) -> &[u8] {
        self.certificate.as_ref()
    }
}

impl ZoneRecord for SmimeaRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        match index {
            0 => self.usage = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse usage param"))?,
            1 => self.selector = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse selector param"))?,
            2 => self.matching_type = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse matching_type param"))?,
            3 => self.certificate = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse certificate param"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        }

        Ok(())
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for SmimeaRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {} {}", self.get_type().to_string(),
               self.usage,
               self.selector,
               self.matching_type,
               hex::encode(&self.certificate))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x1a, 0x1, 0x2, 0x3, 0x30, 0x25, 0x1f, 0xd9, 0x47, 0x7c, 0xfd, 0x17, 0x6a, 0x98, 0x3a, 0x34, 0xe1, 0x90, 0xbb, 0x7d, 0xa3, 0xc2, 0xf3, 0x7c, 0xa, 0xba, 0x95 ];
    let record = SmimeaRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
