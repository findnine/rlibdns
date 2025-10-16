use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::ZoneReaderError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxtRRData {
    data: Vec<String>
}

impl Default for TxtRRData {

    fn default() -> Self {
        Self {
            data: Vec::new()
        }
    }
}

impl RRData for TxtRRData {

    fn from_bytes(buf: &[u8], off: usize, len: usize) -> Result<Self, RRDataError> {
        let mut off = off;
        let mut data = Vec::new();

        while off < len {
            let data_length = buf[off] as usize;
            let record = String::from_utf8(buf[off + 1..off + 1 + data_length].to_vec())
                .map_err(|e| RRDataError(e.to_string()))?;
            data.push(record);
            off += data_length+1;
        }

        Ok(Self {
            data
        })
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(78);

        for record in &self.data {
            buf.push(record.len() as u8);
            buf.extend_from_slice(record.as_bytes());
        }

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

impl TxtRRData {

    pub fn new(data: Vec<String>) -> Self {
        Self {
            data
        }
    }

    pub fn add_data(&mut self, data: &str) {
        self.data.push(data.to_string());
    }

    pub fn get_data(&self) -> &Vec<String> {
        self.data.as_ref()
    }

    pub fn get_data_mut(&mut self) -> &mut Vec<String> {
        self.data.as_mut()
    }
}

impl ZoneRRData for TxtRRData {

    fn set_data(&mut self, _index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(self.data.push(value.to_string()))
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for TxtRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data.iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(" "))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x9, 0x76, 0x3d, 0x62, 0x6c, 0x61, 0x20, 0x62, 0x6c, 0x61 ];
    let record = TxtRRData::from_bytes(&buf, 0, buf.len()).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
