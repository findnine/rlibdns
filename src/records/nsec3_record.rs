use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::hex;
use crate::zone::inter::zone_record::ZoneRecord;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct NSec3Record {
    algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
    next_hash: Vec<u8>,
    types: Vec<RRTypes>
}

impl Default for NSec3Record {

    fn default() -> Self {
        Self {
            algorithm: 0,
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
            next_hash: Vec::new(),
            types: Vec::new()
        }
    }
}

impl RecordBase for NSec3Record {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let mut length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let algorithm = buf[off+2];
        let flags = buf[off+3];
        let iterations = u16::from_be_bytes([buf[off+4], buf[off+5]]);

        length += off+2;

        let salt_length = buf[off+6] as usize;
        let salt = buf[off + 7..off + 7 + salt_length].to_vec();

        let mut off = off+7+salt_length;
        let next_hash_length = buf[off+1] as usize;
        let next_hash = buf[off + 1..off + 1 + next_hash_length].to_vec();
        off += 1+next_hash_length;


        let mut types = Vec::new();

        while off < length {
            if off+2 > length {
                return Err(RecordError("truncated NSEC window header".to_string()));
            }

            let window = buf[off];
            let data_length = buf[off + 1] as usize;
            off += 2;

            if data_length == 0 || data_length > 32 {
                return Err(RecordError("invalid NSEC window length".to_string()));
            }

            if off + data_length > length {
                return Err(RecordError("truncated NSEC bitmap".to_string()));
            }

            for (i, &byte) in buf[off..off + data_length].iter().enumerate() {
                for bit in 0..8 {
                    if (byte & (1 << (7 - bit))) != 0 {
                        let _type = RRTypes::try_from((window as u16) * 256 + (i as u16 * 8 + bit as u16))
                            .map_err(|e| RecordError(e.to_string()))?;
                        types.push(_type);
                    }
                }
            }

            off += data_length;
        }

        Ok(Self {
            algorithm,
            flags,
            iterations,
            salt,
            next_hash,
            types
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 2];

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::NSec3
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

impl NSec3Record {

    pub fn new(algorithm: u8, flags: u8, iterations: u16, salt: Vec<u8>, next_hash: Vec<u8>, types: Vec<RRTypes>) -> Self {
        Self {
            algorithm,
            flags,
            iterations,
            salt,
            next_hash,
            types
        }
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn get_algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    pub fn get_flags(&self) -> u8 {
        self.flags
    }

    pub fn set_iterations(&mut self, iterations: u16) {
        self.iterations = iterations;
    }

    pub fn get_iterations(&self) -> u16 {
        self.iterations
    }

    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }

    pub fn get_salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn set_next_hash(&mut self, next_hash: &[u8]) {
        self.next_hash = next_hash.to_vec();
    }

    pub fn get_next_hash(&self) -> &[u8] {
        &self.next_hash
    }

    pub fn add_type(&mut self, _type: RRTypes) {
        self.types.push(_type);
    }

    pub fn get_types(&self) -> &Vec<RRTypes> {
        self.types.as_ref()
    }

    pub fn get_types_mut(&mut self) -> &mut Vec<RRTypes> {
        self.types.as_mut()
    }
}

impl ZoneRecord for NSec3Record {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse algorithm param for record type {}", self.get_type())))?,
            1 => self.flags = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse flags param for record type {}", self.get_type())))?,
            2 => self.iterations = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse iterations param for record type {}", self.get_type())))?,
            3 => self.salt = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse salt param for record type {}", self.get_type())))?,
            4 => self.next_hash = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse next_hash param for record type {}", self.get_type())))?,
            _ => self.types.push(RRTypes::from_str(value)
                .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse rr_types param for record type {}", self.get_type())))?)
        })
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for NSec3Record {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {} {} {}", self.get_type().to_string(),
               self.algorithm,
               self.flags,
               self.iterations,
               hex::encode(&self.salt),
               self.types.iter()
                   .map(|t| t.to_string())
                   .collect::<Vec<_>>()
                   .join(" "))
    }
}

#[test]
fn test() {
    let buf = vec![ ];
    let record = NSec3Record::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
