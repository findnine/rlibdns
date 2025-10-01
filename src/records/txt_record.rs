use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};

#[derive(Clone, Debug)]
pub struct TxtRecord {
    pub(crate) data: Vec<String>
}

impl Default for TxtRecord {

    fn default() -> Self {
        Self {
            data: Vec::new()
        }
    }
}

impl RecordBase for TxtRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let mut off = off;

        let data_length = off+2+u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        off += 2;

        let mut data = Vec::new();

        while off < data_length {
            let length = buf[off] as usize;
            let record = String::from_utf8(buf[off + 1..off + 1 + length].to_vec()).unwrap();
            data.push(record);
            off += length+1;
        }

        Ok(Self {
            data
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, String> {
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

impl TxtRecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
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

impl fmt::Display for TxtRecord {

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
    let record = TxtRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
