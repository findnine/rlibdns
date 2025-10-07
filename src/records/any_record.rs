use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};

#[derive(Clone, Debug)]
pub struct AnyRecord;

impl Default for AnyRecord {

    fn default() -> Self {
        Self
    }
}

impl RecordBase for AnyRecord {

    fn from_bytes(_buf: &[u8], _off: usize) -> Result<Self, RecordError> {
        Ok(Self)
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        Ok(0u16.to_be_bytes().to_vec())
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Any
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

impl AnyRecord {

    pub fn new() -> Self {
        Self
    }
}

impl fmt::Display for AnyRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}", self.get_type().to_string())
    }
}
