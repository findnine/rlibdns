use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::message::MessageError;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::pack_fqdn_compressed;

#[derive(Debug, Clone)]
pub struct Record {
    fqdn: String,
    class: RRClasses,
    rtype: RRTypes,
    ttl: u32,
    data: Option<Box<dyn RRData>>
}

impl Record {

    pub fn new(fqdn: &str, class: RRClasses, rtype: RRTypes, ttl: u32, data: Option<Box<dyn RRData>>) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            class,
            rtype,
            ttl,
            data
        }
    }

    /*
    pub fn from_bytes(buf: &[u8], off: usize, _len: usize) -> Result<Self, MessageError> {
        let (fqdn, fqdn_length) = unpack_fqdn(buf, off);
        let mut off = off+fqdn_length;

        let rtype = RRTypes::try_from(u16::from_be_bytes([buf[off], buf[off+1]])).map_err(|e| MessageError::RecordError(e.to_string()))?;


        Ok(Self {
            fqdn,
            rtype
        })
    }
    */

    pub fn to_wire(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, MessageError> {
        let fqdn = pack_fqdn_compressed(&self.fqdn, compression_data, off);

        let mut buf = Vec::new();

        match &self.data {
            Some(data) => {
                let data = data.to_wire(compression_data, off).map_err(|e| MessageError::RecordError(e.to_string()))?;

                buf.extend_from_slice(&fqdn);
                buf.extend_from_slice(&self.rtype.code().to_be_bytes());

                buf.extend_from_slice(&self.class.code().to_be_bytes());
                buf.extend_from_slice(&self.ttl.to_be_bytes());

                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(&data);
            }
            None => {
                buf.extend_from_slice(&fqdn);
                buf.extend_from_slice(&self.rtype.code().to_be_bytes());

                buf.extend_from_slice(&self.class.code().to_be_bytes());
                buf.extend_from_slice(&self.ttl.to_be_bytes());

                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        Ok(buf)
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = fqdn.to_string();
    }

    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn class(&self) -> RRClasses {
        self.class
    }

    pub fn set_type(&mut self, rtype: RRTypes) {
        self.rtype = rtype;
    }

    pub fn rtype(&self) -> RRTypes {
        self.rtype
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_data(&mut self, data: Option<Box<dyn RRData>>) {
        self.data = data;
    }

    pub fn data(&self) -> Option<&Box<dyn RRData>> {
        self.data.as_ref()
    }
}

impl fmt::Display for Record {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<24}{:<8}{:<8}{:<8}{}",
                 format!("{}.", self.fqdn),
                 self.ttl,
                 self.rtype.to_string(),
                 self.class.to_string(),
                 self.data.as_ref().map(|d| d.to_string()).unwrap_or(String::new()))
    }
}
