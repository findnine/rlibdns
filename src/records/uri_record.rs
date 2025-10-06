use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::zone::inter::zone_record::ZoneRecord;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct UriRecord {
    priority: u16,
    weight: u16,
    target: Option<String>
}

impl Default for UriRecord {

    fn default() -> Self {
        Self {
            priority: 0,
            weight: 0,
            target: None
        }
    }
}

impl RecordBase for UriRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]);
        if length == 0 {
            return Ok(Default::default());
        }

        let priority = u16::from_be_bytes([buf[off+2], buf[off+3]]);
        let weight = u16::from_be_bytes([buf[off+4], buf[off+5]]);

        let target = String::from_utf8(buf[off+6..off+2+length as usize].to_vec())
            .map_err(|e| RecordError(e.to_string()))?;

        Ok(Self {
            priority,
            weight,
            target: Some(target)
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 6];

        buf.splice(2..4, self.priority.to_be_bytes());
        buf.splice(4..6, self.weight.to_be_bytes());

        buf.extend_from_slice(self.target.as_ref().ok_or_else(|| RecordError("target param was not set".to_string()))?.as_bytes());

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Uri
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

impl UriRecord {

    pub fn new(priority: u16, weight: u16, target: &str) -> Self {
        Self {
            priority,
            weight,
            target: Some(target.to_string())
        }
    }

    pub fn set_priority(&mut self, priority: u16) {
        self.priority = priority;
    }

    pub fn get_priority(&self) -> u16 {
        self.priority
    }

    pub fn set_weight(&mut self, weight: u16) {
        self.weight = weight;
    }

    pub fn get_weight(&self) -> u16 {
        self.weight
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn get_target(&self) -> Option<&String> {
        self.target.as_ref()
    }
}

impl ZoneRecord for UriRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        match index {
            0 => self.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse priority param"))?,
            1 => self.weight = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse weight param"))?,
            2 => self.target = Some(value.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        }

        Ok(())
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for UriRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} \"{}\"", self.get_type().to_string(),
               self.priority,
               self.weight,
               self.target.as_ref().unwrap_or(&String::new()))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x16, 0x0, 0x1, 0x0, 0x1, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3a, 0x2f, 0x2f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 ];
    let record = UriRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
