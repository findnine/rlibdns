use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::ZoneReaderError;

#[derive(Clone, Debug)]
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

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let mut length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        length += off+2;
        let mut off = off+2;
        let mut data = Vec::new();

        while off < length {
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

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 2];

        for record in &self.data {
            buf.push(record.len() as u8);
            buf.extend_from_slice(record.as_bytes());
        }

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Txt
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
        write!(f, "{:<8}{}", self.get_type().to_string(),
               self.data.iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(" "))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0xa, 0x9, 0x76, 0x3d, 0x62, 0x6c, 0x61, 0x20, 0x62, 0x6c, 0x61 ];
    let record = TxtRRData::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
