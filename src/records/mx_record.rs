use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Clone, Debug)]
pub struct MxRecord {
    pub(crate) priority: u16,
    pub(crate) server: Option<String>
}

impl Default for MxRecord {

    fn default() -> Self {
        Self {
            priority: 0,
            server: None
        }
    }
}

impl RecordBase for MxRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let priority = u16::from_be_bytes([buf[off+2], buf[off+3]]);

        let (server, _) = unpack_fqdn(buf, off+4);

        Ok(Self {
            priority,
            server: Some(server)
        })
    }

    fn to_bytes(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 4];

        buf.splice(2..4, self.priority.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.server.as_ref()
            .ok_or_else(|| RecordError("server param was not set".to_string()))?, compression_data, off+4, true));

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Mx
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

impl MxRecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
        }
    }

    pub fn set_priority(&mut self, priority: u16) {
        self.priority = priority;
    }

    pub fn get_priority(&self) -> u16 {
        self.priority
    }

    pub fn set_server(&mut self, server: &str) {
        self.server = Some(server.to_string());
    }

    pub fn get_server(&self) -> Option<String> {
        self.server.clone()
    }
}

impl fmt::Display for MxRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {}", self.get_type().to_string(),
               self.priority,
               format!("{}.", self.server.as_ref().unwrap()))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0xd, 0x0, 0x1, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0 ];
    let record = MxRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
