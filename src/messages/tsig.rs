use std::fmt;
use std::fmt::Formatter;
use crate::keyring::key::Key;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::wire::{FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::tsig_rr_data::TSigRRData;
use crate::utils::hash::hmac::hmac;
use crate::utils::hash::sha256::Sha256;

#[derive(Debug, Clone)]
pub struct TSig {
    owner: Option<String>,
    data: TSigRRData,
    signed_payload: Vec<u8>
}

impl TSig {

    pub fn new(owner: &str, data: TSigRRData) -> Self {
        Self {
            owner: Some(owner.to_string()),
            data,
            signed_payload: Vec::new()
        }
    }

    pub fn verify(&self, key: &Key) -> bool {
        let calc = hmac::<Sha256>(key.secret(), &self.signed_payload);
        //self.mac.len() == calc.len() && self.mac.iter().zip(calc).fold(0u8, |d,(a,b)| d | (a^b)) == 0
        todo!()
    }
}

impl FromWireLen for TSig {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {

        //Ok(Self {
        //})
        todo!()
    }
}

impl ToWire for TSig {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {

        todo!()
    }
}

impl fmt::Display for TSig {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<24}{:<8}{:<8}{:<8}{}",
               format!("{}.", self.owner.as_ref().unwrap()),
               0,
               RRTypes::TSig.to_string(),
               RRClasses::Any,
               self.data)
    }
}
