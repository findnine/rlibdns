use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};

#[derive(Clone, Debug)]
pub struct HInfoRecord {
    pub(crate) cpu: Option<String>,
    pub(crate) os: Option<String>
}

impl Default for HInfoRecord {

    fn default() -> Self {
        Self {
            cpu: None,
            os: None
        }
    }
}

impl RecordBase for HInfoRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let length = buf[off+2] as usize;
        let cpu = String::from_utf8(buf[off+3..off+3+length].to_vec()).unwrap();
        let off = off+3+length;

        let length = buf[off] as usize;
        let os = String::from_utf8(buf[off+1..off+1+length].to_vec()).unwrap();

        Ok(Self {
            cpu: Some(cpu),
            os: Some(os)
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 2];

        let cpu = self.cpu.as_ref().unwrap().as_bytes();
        buf.push(cpu.len() as u8);
        buf.extend_from_slice(cpu);

        let os = self.os.as_ref().unwrap().as_bytes();
        buf.push(os.len() as u8);
        buf.extend_from_slice(os);

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::HInfo
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

impl HInfoRecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
        }
    }

    pub fn set_cpu(&mut self, cpu: &str) {
        self.cpu = Some(cpu.to_string());
    }

    pub fn get_cpu(&self) -> Option<String> {
        self.cpu.clone()
    }

    pub fn set_os(&mut self, os: &str) {
        self.os = Some(os.to_string());
    }

    pub fn get_os(&self) -> Option<String> {
        self.os.clone()
    }
}

impl fmt::Display for HInfoRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}\"{}\" \"{}\"", self.get_type().to_string(),
               self.cpu.as_ref().unwrap(),
               self.os.as_ref().unwrap())
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x5, 0x3, 0x41, 0x4d, 0x44, 0x0 ];
    let record = HInfoRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
