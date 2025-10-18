use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::hex;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NSec3ParamRRData {
    algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>
}

impl Default for NSec3ParamRRData {

    fn default() -> Self {
        Self {
            algorithm: 0,
            flags: 0,
            iterations: 0,
            salt: Vec::new()
        }
    }
}

impl RRData for NSec3ParamRRData {

    fn from_bytes(buf: &[u8], off: usize, _len: usize) -> Result<Self, RRDataError> {
        let algorithm = buf[off];
        let flags = buf[off+1];
        let iterations = u16::from_be_bytes([buf[off+2], buf[off+3]]);

        let salt_length = buf[off+4] as usize;
        let salt = buf[off + 5..off + 5 + salt_length].to_vec();

        Ok(Self {
            algorithm,
            flags,
            iterations,
            salt
        })
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(22);

        buf.push(self.algorithm);
        buf.push(self.flags);
        buf.extend_from_slice(&self.iterations.to_be_bytes());

        buf.push(self.salt.len() as u8);
        buf.extend_from_slice(&self.salt);

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

impl NSec3ParamRRData {

    pub fn new(algorithm: u8, flags: u8, iterations: u16, salt: &[u8]) -> Self {
        Self {
            algorithm,
            flags,
            iterations,
            salt: salt.to_vec()
        }
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn set_iterations(&mut self, iterations: u16) {
        self.iterations = iterations;
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}

impl ZoneRRData for NSec3ParamRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse algorithm param for record type NSEC3PARAM"))?,
            1 => self.flags = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse flags param for record type NSEC3PARAM"))?,
            2 => self.iterations = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse iterations param for record type NSEC3PARAM"))?,
            3 => self.salt = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse salt param for record type NSEC3PARAM"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type NSEC3PARAM"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for NSec3ParamRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}", self.algorithm,
               self.flags,
               self.iterations,
               hex::encode(&self.salt))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x1, 0x0, 0x0, 0x0, 0x0 ];
    let record = NSec3ParamRRData::from_bytes(&buf, 0, buf.len()).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
