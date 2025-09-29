use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
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

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (server, _) = unpack_fqdn(buf, off+2);

        Self {
            server: Some(server)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 2];

        buf.extend_from_slice(&pack_fqdn(self.server.as_ref().unwrap().as_str(), label_map, off+2, true));

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
