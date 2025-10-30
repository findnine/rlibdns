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
    owner: String,
    data: TSigRRData,
    signed_payload: Vec<u8>
}

impl TSig {

    pub fn new(owner: &str, data: TSigRRData) -> Self {
        Self {
            owner: owner.to_string(),
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

        todo!()
    }
}

impl ToWire for TSig {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(&self.owner, true)?;

        RRTypes::TSig.code().to_wire(context)?;

        RRClasses::Any.code().to_wire(context)?;
        0u32.to_wire(context)?;

        let checkpoint = context.pos();
        context.skip(2)?;

        self.data.to_wire(context)?;

        context.patch(checkpoint..checkpoint+2, &((context.pos()-checkpoint-2) as u16).to_be_bytes())
    }
}

impl fmt::Display for TSig {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<24}{:<8}{:<8}{:<8}{}",
               format!("{}.", self.owner),
               0,
               RRTypes::TSig.to_string(),
               RRClasses::Any,
               self.data)
    }
}
