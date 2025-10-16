use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::hex;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshFpRRData {
    class: RRClasses,
    ttl: u32,
    algorithm: u8,
    fingerprint_type: u8,
    fingerprint: Vec<u8>
}

impl Default for SshFpRRData {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            algorithm: 0,
            fingerprint_type: 0,
            fingerprint: Vec::new()
        }
    }
}

impl RRData for SshFpRRData {

    fn from_bytes(buf: &[u8], off: usize, _len: usize) -> Result<Self, RRDataError> {
        let class = RRClasses::try_from(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let algorithm = buf[off+8];
        let fingerprint_type = buf[off+9];

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;

        let fingerprint = buf[off+10..data_length].to_vec();

        Ok(Self {
            class,
            ttl,
            algorithm,
            fingerprint_type,
            fingerprint
        })
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 10]; //40

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf[8] = self.algorithm;
        buf[9] = self.fingerprint_type;

        buf.extend_from_slice(&self.fingerprint);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

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

impl SshFpRRData {

    pub fn new(ttl: u32, class: RRClasses) -> Self {
        Self {
            class,
            ttl,
            ..Self::default()
        }
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn get_algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_fingerprint_type(&mut self, fingerprint_type: u8) {
        self.fingerprint_type = fingerprint_type;
    }

    pub fn get_fingerprint_type(&self) -> u8 {
        self.fingerprint_type
    }

    pub fn set_fingerprint(&mut self, fingerprint: &[u8]) {
        self.fingerprint = fingerprint.to_vec();
    }

    pub fn get_fingerprint(&self) -> &[u8] {
        self.fingerprint.as_ref()
    }
}

impl ZoneRRData for SshFpRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse algorithm param for record type SSHFP"))?,
            1 => self.fingerprint_type = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse fingerprint_type param for record type SSHFP"))?,
            2 => self.fingerprint = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse fingerprint param for record type SSHFP"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type SSHFP"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for SshFpRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.algorithm,
               self.fingerprint_type,
               hex::encode(&self.fingerprint))
    }
}
