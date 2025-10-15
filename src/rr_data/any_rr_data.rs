use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyRRData;

impl Default for AnyRRData {

    fn default() -> Self {
        Self
    }
}

impl RRData for AnyRRData {

    fn from_bytes(_buf: &[u8], _off: usize) -> Result<Self, RRDataError> {
        Ok(Self)
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
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

    fn upcast(self) -> Box<dyn RRData> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn RRData> {
        Box::new(self.clone())
    }

    fn eq_box(&self, other: &dyn RRData) -> bool {
        other.as_any().downcast_ref::<Self>().map_or(false, |o| self == o)
    }
}

impl AnyRRData {

    pub fn new() -> Self {
        Self
    }
}

impl fmt::Display for AnyRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}", self.get_type().to_string())
    }
}
