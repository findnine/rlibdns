use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Clone, Debug)]
pub struct ChARecord {
    pub(crate) network: Option<String>,
    pub(crate) address: u16
}

impl Default for ChARecord {

    fn default() -> Self {
        Self {
            network: None,
            address: 0
        }
    }
}

impl RecordBase for ChARecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let (network, length) = unpack_fqdn(buf, off+2);

        let address = u16::from_be_bytes([buf[off+2+length], buf[off+3+length]]);

        Ok(Self {
            network: Some(network),
            address
        })
    }

    fn to_bytes(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 2];

        buf.extend_from_slice(&pack_fqdn(self.network.as_ref()
            .ok_or_else(|| RecordError("network param was not set".to_string()))?, compression_data, off+2, true));

        buf.extend_from_slice(&self.address.to_be_bytes());

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::A
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

impl ChARecord {

    pub fn new(network: &str, address: u16) -> Self {
        Self {
            network: Some(network.to_string()),
            address
        }
    }

    pub fn set_network(&mut self, network: &str) {
        self.network = Some(network.to_string());
    }

    pub fn get_network(&self) -> Option<&String> {
        self.network.as_ref()
    }

    pub fn set_address(&mut self, address: u16) {
        self.address = address;
    }

    pub fn get_address(&self) -> u16 {
        self.address
    }
}

impl fmt::Display for ChARecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {}", self.get_type().to_string(),
               format!("{}.", self.network.as_ref().unwrap_or(&String::new())),
               self.address)
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0xb, 0x7, 0x43, 0x48, 0x2d, 0x41, 0x44, 0x44, 0x52, 0x0, 0x6, 0x61 ];
    let record = ChARecord::from_bytes(&buf, 0).unwrap();
    println!("{}", record);
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
