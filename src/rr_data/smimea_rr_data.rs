use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::hex;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmimeaRRData {
    usage: u8,
    selector: u8,
    matching_type: u8,
    certificate: Vec<u8>
}

impl Default for SmimeaRRData {

    fn default() -> Self {
        Self {
            usage: 0,
            selector: 0,
            matching_type: 0,
            certificate: Vec::new()
        }
    }
}

impl RRData for SmimeaRRData {

    fn from_bytes(buf: &[u8], off: usize, len: usize) -> Result<Self, RRDataError> {
        let usage = buf[off];
        let selector = buf[off+1];
        let matching_type = buf[off+2];

        let certificate = buf[off+3..len].to_vec();

        Ok(Self {
            usage,
            selector,
            matching_type,
            certificate
        })
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(46);

        buf.push(self.usage);
        buf.push(self.selector);
        buf.push(self.matching_type);

        buf.extend_from_slice(&self.certificate);

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

impl SmimeaRRData {

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

    pub fn usage(&self) -> u8 {
        self.usage
    }

    pub fn set_selector(&mut self, selector: u8) {
        self.selector = selector;
    }

    pub fn selector(&self) -> u8 {
        self.selector
    }

    pub fn set_matching_type(&mut self, matching_type: u8) {
        self.matching_type = matching_type;
    }

    pub fn matching_type(&self) -> u8 {
        self.matching_type
    }

    pub fn set_certificate(&mut self, certificate: &[u8]) {
        self.certificate = certificate.to_vec();
    }

    pub fn certificate(&self) -> &[u8] {
        self.certificate.as_ref()
    }
}

impl ZoneRRData for SmimeaRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.usage = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse usage param for record type SMIMEA"))?,
            1 => self.selector = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse selector param for record type SMIMEA"))?,
            2 => self.matching_type = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse matching_type param for record type SMIMEA"))?,
            3 => self.certificate = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse certificate param for record type SMIMEA"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type SMIMEA"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for SmimeaRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}", self.usage,
               self.selector,
               self.matching_type,
               hex::encode(&self.certificate))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x1, 0x2, 0x3, 0x30, 0x25, 0x1f, 0xd9, 0x47, 0x7c, 0xfd, 0x17, 0x6a, 0x98, 0x3a, 0x34, 0xe1, 0x90, 0xbb, 0x7d, 0xa3, 0xc2, 0xf3, 0x7c, 0xa, 0xba, 0x95 ];
    let record = SmimeaRRData::from_bytes(&buf, 0, buf.len()).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
