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
pub struct DnsKeyRecord {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: Vec<u8>
}

impl Default for DnsKeyRecord {

    fn default() -> Self {
        Self {
            flags: 0,
            protocol: 0,
            algorithm: 0,
            public_key: Vec::new()
        }
    }
}

impl RecordBase for DnsKeyRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
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

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 6];

        buf.splice(2..4, self.flags.to_be_bytes());
        buf[4] = self.protocol;
        buf[5] = self.algorithm;

        buf.extend_from_slice(&self.public_key);

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::DnsKey
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

impl DnsKeyRecord {

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

impl ZoneRecord for DnsKeyRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.flags = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse flags param for record type {}", self.get_type())))?,
            1 => self.protocol = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse protocol param for record type {}", self.get_type())))?,
            2 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse algorithm param for record type {}", self.get_type())))?,
            3 => self.public_key = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse public_key param for record type {}", self.get_type())))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for DnsKeyRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {} {}", self.get_type().to_string(),
               self.flags,
               self.protocol,
               self.algorithm,
               hex::encode(&self.public_key))
    }
}

#[test]
fn test() {
    let buf = vec![ ];
    let record = DnsKeyRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
