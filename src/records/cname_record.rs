use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Clone, Debug)]
pub struct CNameRecord {
    pub(crate) target: Option<String>
}

impl Default for CNameRecord {

    fn default() -> Self {
        Self {
            target: None
        }
    }
}

impl RecordBase for CNameRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (target, _) = unpack_fqdn(buf, off+8);

        Self {
            target: Some(target)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 2];

        buf.extend_from_slice(&pack_fqdn(self.target.as_ref().unwrap().as_str(), label_map, off+2, true));

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::CName
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn upcast(self) -> Box<dyn RecordBase> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }
}

impl CNameRecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
        }
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn get_target(&self) -> Option<String> {
        self.target.clone()
    }
}

impl fmt::Display for CNameRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{}", self.get_type().to_string(),
               format!("{}.", self.target.as_ref().unwrap()))
    }
}
