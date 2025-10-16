use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::base64;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsKeyRRData {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: Vec<u8>
}

impl Default for DnsKeyRRData {

    fn default() -> Self {
        Self {
            flags: 0,
            protocol: 0,
            algorithm: 0,
            public_key: Vec::new()
        }
    }
}

impl RRData for DnsKeyRRData {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let mut length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let flags = u16::from_be_bytes([buf[off+2], buf[off+3]]);
        /*
        Flags: 0x0100
            .... ...1 .... .... = Zone Key: This is the zone key for specified zone
            .... .... 0... .... = Key Revoked: No
            .... .... .... ...0 = Key Signing Key: No
            0000 000. .000 000. = Key Signing Key: 0x0000
        */

        let protocol = buf[off+4];
        let algorithm = buf[off+5];

        length = off+2;

        let public_key = buf[off+6..length].to_vec();

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key
        })
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(96);

        unsafe { buf.set_len(2); };

        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.push(self.protocol);
        buf.push(self.algorithm);

        buf.extend_from_slice(&self.public_key);

        let length = (buf.len()-2) as u16;
        buf[0..2].copy_from_slice(&length.to_be_bytes());

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

impl DnsKeyRRData {

    pub fn new(flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8>) -> Self {
        Self {
            flags,
            protocol,
            algorithm,
            public_key
        }
    }

    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }

    pub fn get_flags(&self) -> u16 {
        self.flags
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.protocol = protocol;
    }

    pub fn get_protocol(&self) -> u8 {
        self.protocol
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn get_algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_public_key(&mut self, public_key: &[u8]) {
        self.public_key = public_key.to_vec();
    }

    pub fn get_public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl ZoneRRData for DnsKeyRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.flags = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse flags param for record type DNSKEY"))?,
            1 => self.protocol = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse protocol param for record type DNSKEY"))?,
            2 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse algorithm param for record type DNSKEY"))?,
            3 => self.public_key = base64::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse public_key param for record type DNSKEY"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type DNSKEY"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for DnsKeyRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}", self.flags,
               self.protocol,
               self.algorithm,
               base64::encode(&self.public_key))
    }
}

#[test]
fn test() {
    let buf = vec![ ];
    let record = DnsKeyRRData::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
