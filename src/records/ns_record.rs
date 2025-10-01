use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Clone, Debug)]
pub struct NsRecord {
    pub(crate) server: Option<String>
}

impl Default for NsRecord {

    fn default() -> Self {
        Self {
            server: None
        }
    }
}

impl RecordBase for NsRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (server, _) = unpack_fqdn(buf, off+2);

        Ok(Self {
            server: Some(server)
        })
    }

    fn to_bytes(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 2];

        buf.extend_from_slice(&pack_fqdn(self.server.as_ref()
            .ok_or_else(|| RecordError("server param was not set".to_string()))?, compression_data, off+2, false));

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Ns
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

impl NsRecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
        }
    }

    pub fn set_server(&mut self, server: &str) {
        self.server = Some(server.to_string());
    }

    pub fn get_server(&self) -> Option<String> {
        self.server.clone()
    }
}

impl fmt::Display for NsRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{}", self.get_type().to_string(),
               format!("{}.", self.server.as_ref().unwrap()))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0xf, 0x3, 0x6e, 0x73, 0x32, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0 ];
    let record = NsRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
