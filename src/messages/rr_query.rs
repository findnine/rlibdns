use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::message::MessageError;
use crate::messages::wire::{FromWire, FromWireContext, ToWire, ToWireContext, WireError};
use crate::utils::fqdn_utils::{pack_fqdn, pack_fqdn_compressed, unpack_fqdn};

#[derive(Debug, Clone)]
pub struct RRQuery {
    fqdn: String,
    rtype: RRTypes,
    class: RRClasses
}

impl RRQuery {

    pub fn new(fqdn: &str, rtype: RRTypes, class: RRClasses) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            rtype,
            class
        }
    }

    pub fn from_bytes(buf: &[u8], off: &mut usize) -> Result<Self, MessageError> {
        let (fqdn, fqdn_length) = unpack_fqdn(buf, *off);
        *off += fqdn_length;

        let rtype = RRTypes::try_from(u16::from_be_bytes([buf[*off], buf[*off+1]])).map_err(|e| MessageError::RecordError(e.to_string()))?;
        let class = RRClasses::try_from(u16::from_be_bytes([buf[*off+2], buf[*off+3]])).map_err(|e| MessageError::RecordError(e.to_string()))?;
        *off += 4;

        Ok(Self {
            fqdn,
            rtype,
            class
        })
    }

    pub fn to_wire1(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Vec<u8> {
        let mut buf = pack_fqdn_compressed(&self.fqdn, compression_data, off);

        buf.extend_from_slice(&self.rtype.code().to_be_bytes());
        buf.extend_from_slice(&self.class.code().to_be_bytes());

        buf
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = pack_fqdn(&self.fqdn);

        buf.extend_from_slice(&self.rtype.code().to_be_bytes());
        buf.extend_from_slice(&self.class.code().to_be_bytes());

        buf
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = fqdn.to_string();
    }

    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn set_rtype(&mut self, rtype: RRTypes) {
        self.rtype = rtype;
    }

    pub fn rtype(&self) -> RRTypes {
        self.rtype
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn class(&self) -> RRClasses {
        self.class
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl FromWire for RRQuery {

    fn from_wire(context: &mut FromWireContext) -> Result<Self, WireError> {
        let fqdn = context.name()?;

        let rtype = RRTypes::try_from(u16::from_wire(context)?).map_err(|e| WireError::Format(e.to_string()))?;
        let class = RRClasses::try_from(u16::from_wire(context)?).map_err(|e| WireError::Format(e.to_string()))?;

        Ok(Self {
            fqdn,
            rtype,
            class
        })
    }
}

impl ToWire for RRQuery {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(self.fqdn())?;

        self.rtype.code().to_wire(context)?;
        self.class.code().to_wire(context)?;

        Ok(())
    }
}

impl fmt::Display for RRQuery {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<31}{:<8}{}", format!("{}.", self.fqdn), self.class.to_string(), self.rtype)
    }
}
