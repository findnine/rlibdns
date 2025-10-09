use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::message::MessageError;
use crate::utils::fqdn_utils::{pack_fqdn, pack_fqdn_compressed, unpack_fqdn};

#[derive(Debug, Clone)]
pub struct RRQuery {
    fqdn: String,
    _type: RRTypes,
    class: RRClasses
}

impl RRQuery {

    pub fn new(fqdn: &str, _type: RRTypes, class: RRClasses) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            _type,
            class
        }
    }

    pub fn from_bytes(buf: &[u8], off: &mut usize) -> Result<Self, MessageError> {
        let (fqdn, len) = unpack_fqdn(buf, *off);
        *off += len;

        let _type = RRTypes::try_from(u16::from_be_bytes([buf[*off], buf[*off+1]])).map_err(|e| MessageError::RecordError(e.to_string()))?;
        let class = RRClasses::try_from(u16::from_be_bytes([buf[*off+2], buf[*off+3]])).map_err(|e| MessageError::RecordError(e.to_string()))?;
        *off += 4;

        Ok(Self {
            fqdn,
            _type,
            class
        })
    }

    pub fn to_bytes_compressed(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Vec<u8> {
        let mut buf = pack_fqdn_compressed(&self.fqdn, compression_data, off);

        buf.extend_from_slice(&self._type.get_code().to_be_bytes());
        buf.extend_from_slice(&self.class.get_code().to_be_bytes());

        buf
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = pack_fqdn(&self.fqdn);

        buf.extend_from_slice(&self._type.get_code().to_be_bytes());
        buf.extend_from_slice(&self.class.get_code().to_be_bytes());

        buf
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = fqdn.to_string();
    }

    pub fn get_fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn set_type(&mut self, _type: RRTypes) {
        self._type = _type;
    }

    pub fn get_type(&self) -> RRTypes {
        self._type
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl fmt::Display for RRQuery {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<31}{:<8}{}", format!("{}.", self.fqdn), self.class.to_string(), self._type)
    }
}
