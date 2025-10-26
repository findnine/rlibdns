use std::str::FromStr;
use crate::keyring::inter::algorithms::Algorithms;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::RRDataError;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Debug, Clone)]
pub struct TSig {
    algorithm: Option<Algorithms>,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
    data: Vec<u8>,

    signed_payload: Vec<u8>
}

impl TSig {

    pub fn new(algorithm: Algorithms, time_signed: u64, fudge: u16, mac: Vec<u8>, original_id: u16, error: u16, data: Vec<u8>) -> Self {
        Self {
            algorithm: Some(algorithm),
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            data,
            signed_payload: Vec::new()
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let (algorithm, algorithm_length) = unpack_fqdn(buf, 0);
        let algorithm = Algorithms::from_str(&algorithm)
            .map_err(|e| RRDataError(e.to_string()))?;
        let mut i = algorithm_length;

        let time_signed = ((buf[i] as u64) << 40)
            | ((buf[i+1] as u64) << 32)
            | ((buf[i+2] as u64) << 24)
            | ((buf[i+3] as u64) << 16)
            | ((buf[i+4] as u64) << 8)
            |  (buf[i+5] as u64);
        let fudge = u16::from_be_bytes([buf[i+6], buf[i+7]]);

        let mac_length = 10+u16::from_be_bytes([buf[i+8], buf[i+9]]) as usize;
        let mac = buf[i+10..i+mac_length].to_vec();
        i += mac_length;

        let original_id = u16::from_be_bytes([buf[i], buf[i+1]]);
        let error = u16::from_be_bytes([buf[i+2], buf[i+3]]);

        let data_length = i+6+u16::from_be_bytes([buf[i+4], buf[i+5]]) as usize;
        let data = buf[i+6..data_length].to_vec();

        Ok(Self {
            algorithm: Some(algorithm),
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            data,
            signed_payload: Vec::new()
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(158);

        buf.extend_from_slice(&pack_fqdn(&self.algorithm.as_ref()
            .ok_or_else(|| RRDataError("algorithm param was not set".to_string()))?.to_string())); //PROBABLY NO COMPRESS

        buf.extend_from_slice(&[
            ((self.time_signed >> 40) & 0xFF) as u8,
            ((self.time_signed >> 32) & 0xFF) as u8,
            ((self.time_signed >> 24) & 0xFF) as u8,
            ((self.time_signed >> 16) & 0xFF) as u8,
            ((self.time_signed >>  8) & 0xFF) as u8,
            ( self.time_signed        & 0xFF) as u8
        ]);
        buf.extend_from_slice(&self.fudge.to_be_bytes());

        buf.extend_from_slice(&(self.mac.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.mac);

        buf.extend_from_slice(&self.original_id.to_be_bytes());
        buf.extend_from_slice(&self.error.to_be_bytes());

        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

        Ok(buf)
    }

    pub fn set_algorithm(&mut self, algorithm: Algorithms) {
        self.algorithm = Some(algorithm);
    }

    pub fn algorithm(&self) -> Option<&Algorithms> {
        self.algorithm.as_ref()
    }

    pub fn set_time_signed(&mut self, time_signed: u64) {
        self.time_signed = time_signed;
    }

    pub fn time_signed(&self) -> u64 {
        self.time_signed
    }

    pub fn set_fudge(&mut self, fudge: u16) {
        self.fudge = fudge;
    }

    pub fn fudge(&self) -> u16 {
        self.fudge
    }

    pub fn set_mac(&mut self, mac: &[u8]) {
        self.mac = mac.to_vec();
    }

    pub fn mac(&self) -> &[u8] {
        self.mac.as_ref()
    }

    pub fn set_original_id(&mut self, original_id: u16) {
        self.original_id = original_id;
    }

    pub fn original_id(&self) -> u16 {
        self.original_id
    }

    pub fn set_error(&mut self, error: u16) {
        self.error = error;
    }

    pub fn error(&self) -> u16 {
        self.error
    }

    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        self.signed_payload = payload.to_vec();
    }

    pub fn payload(&self) -> &[u8] {
        &self.signed_payload
    }
}

impl FromWireLen for TSig {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let algorithm = Algorithms::from_str(&context.name()?)
            .map_err(|e| WireError::Format(e.to_string()))?;

        let time_signed = context.take(6)?;
        let time_signed = ((time_signed[0] as u64) << 40)
            | ((time_signed[1] as u64) << 32)
            | ((time_signed[2] as u64) << 24)
            | ((time_signed[3] as u64) << 16)
            | ((time_signed[4] as u64) << 8)
            |  (time_signed[5] as u64);
        let fudge = u16::from_wire(context)?;

        let mac_length = u16::from_wire(context)? as usize;
        let mac = context.take(mac_length)?.to_vec();

        let original_id = u16::from_wire(context)?;
        let error = u16::from_wire(context)?;

        let data_length = u16::from_wire(context)? as usize;
        let data = context.take(data_length)?.to_vec();

        Ok(Self {
            algorithm: Some(algorithm),
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            data,
            signed_payload: Vec::new()
        })
    }
}

impl ToWire for TSig {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(&self.algorithm.as_ref()
            .ok_or_else(|| WireError::Format("algorithm param was not set".to_string()))?.to_string(), true)?; //PROBABLY NO COMPRESS

        context.write(&[
            ((self.time_signed >> 40) & 0xFF) as u8,
            ((self.time_signed >> 32) & 0xFF) as u8,
            ((self.time_signed >> 24) & 0xFF) as u8,
            ((self.time_signed >> 16) & 0xFF) as u8,
            ((self.time_signed >>  8) & 0xFF) as u8,
            ( self.time_signed        & 0xFF) as u8
        ])?;
        self.fudge.to_wire(context)?;

        (self.mac.len() as u16).to_wire(context)?;
        context.write(&self.mac)?;

        self.original_id.to_wire(context)?;
        self.error.to_wire(context)?;

        (self.data.len() as u16).to_wire(context)?;
        context.write(&self.data)
    }
}
