use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HInfoRRData {
    cpu: Option<String>,
    os: Option<String>
}

impl Default for HInfoRRData {

    fn default() -> Self {
        Self {
            cpu: None,
            os: None
        }
    }
}

impl RRData for HInfoRRData {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]);
        if length == 0 {
            return Ok(Default::default());
        }

        let data_length = buf[off+2] as usize;
        let cpu = String::from_utf8(buf[off+3..off+3+data_length].to_vec()).unwrap();
        let off = off+3+data_length;

        let data_length = buf[off] as usize;
        let os = String::from_utf8(buf[off+1..off+1+data_length].to_vec()).unwrap();

        Ok(Self {
            cpu: Some(cpu),
            os: Some(os)
        })
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(48);

        unsafe { buf.set_len(2); };

        let cpu = self.cpu.as_ref().unwrap().as_bytes();
        buf.push(cpu.len() as u8);
        buf.extend_from_slice(cpu);

        let os = self.os.as_ref().unwrap().as_bytes();
        buf.push(os.len() as u8);
        buf.extend_from_slice(os);

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

impl HInfoRRData {

    pub fn new(cpu: &str, os: &str) -> Self {
        Self {
            cpu: Some(cpu.to_string()),
            os: Some(os.to_string())
        }
    }

    pub fn set_cpu(&mut self, cpu: &str) {
        self.cpu = Some(cpu.to_string());
    }

    pub fn get_cpu(&self) -> Option<&String> {
        self.cpu.as_ref()
    }

    pub fn set_os(&mut self, os: &str) {
        self.os = Some(os.to_string());
    }

    pub fn get_os(&self) -> Option<&String> {
        self.os.as_ref()
    }
}

impl ZoneRRData for HInfoRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.cpu = Some(value.to_string()),
            1 => self.os = Some(value.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type HINFO"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for HInfoRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\" \"{}\"", self.cpu.as_ref().unwrap_or(&String::new()),
               self.os.as_ref().unwrap_or(&String::new()))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x5, 0x3, 0x41, 0x4d, 0x44, 0x0 ];
    let record = HInfoRRData::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
