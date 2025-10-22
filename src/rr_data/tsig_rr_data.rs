use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, pack_fqdn_compressed, unpack_fqdn};
use crate::utils::hex;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TSigRRData {
    algorithm_name: Option<String>,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
    data: Vec<u8>
}

impl Default for TSigRRData {

    fn default() -> Self {
        Self {
            algorithm_name: None,
            time_signed: 0,
            fudge: 0,
            mac: Vec::new(),
            original_id: 0,
            error: 0,
            data: Vec::new()
        }
    }
}

impl RRData for TSigRRData {

    fn from_bytes(buf: &[u8], off: usize, _len: usize) -> Result<Self, RRDataError> {
        let mut off = off;

        let (algorithm_name, algorithm_name_length) = unpack_fqdn(buf, off);
        off += algorithm_name_length;

        let time_signed = ((buf[off] as u64) << 40)
                | ((buf[off+1] as u64) << 32)
                | ((buf[off+2] as u64) << 24)
                | ((buf[off+3] as u64) << 16)
                | ((buf[off+4] as u64) << 8)
                |  (buf[off+5] as u64);
        let fudge = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let mac_length = 10+u16::from_be_bytes([buf[off+8], buf[off+9]]) as usize;
        let mac = buf[off + 10..off + mac_length].to_vec();
        off += mac_length;

        let original_id = u16::from_be_bytes([buf[off], buf[off+1]]);
        let error = u16::from_be_bytes([buf[off+2], buf[off+3]]);

        let data_length = off+6+u16::from_be_bytes([buf[off+4], buf[off+5]]) as usize;
        let data = buf[off+6..data_length].to_vec();

        Ok(Self {
            algorithm_name: Some(algorithm_name),
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            data
        })
    }

    fn to_wire1(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(158);

        buf.extend_from_slice(&pack_fqdn_compressed(self.algorithm_name.as_ref()
            .ok_or_else(|| RRDataError("algorithm_name param was not set".to_string()))?, compression_data, off)); //PROBABLY NO COMPRESS

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

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(158);

        buf.extend_from_slice(&pack_fqdn(self.algorithm_name.as_ref()
            .ok_or_else(|| RRDataError("algorithm_name param was not set".to_string()))?)); //PROBABLY NO COMPRESS

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

    fn upcast(self) -> Box<dyn RRData> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RRData> {
        Box::new(self.clone())
    }

    fn eq_box(&self, other: &dyn RRData) -> bool {
        other.as_any().downcast_ref::<Self>().map_or(false, |o| self == o)
    }
}

impl TSigRRData {

    pub fn new(algorithm_name: &str, time_signed: u64, fudge: u16, mac: &[u8], original_id: u16, error: u16, data: &[u8]) -> Self {
        Self {
            algorithm_name: Some(algorithm_name.to_string()),
            time_signed,
            fudge,
            mac: mac.to_vec(),
            original_id,
            error,
            data: data.to_vec()
        }
    }

    pub fn set_algorithm_name(&mut self, algorithm_name: &str) {
        self.algorithm_name = Some(algorithm_name.to_string());
    }

    pub fn algorithm_name(&self) -> Option<&String> {
        self.algorithm_name.as_ref()
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
}

impl FromWireLen for TSigRRData {

    fn from_wire(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let algorithm_name = context.name()?;

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
            algorithm_name: Some(algorithm_name),
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            data
        })
    }
}

impl ToWire for TSigRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(self.algorithm_name.as_ref()
            .ok_or_else(|| WireError::Format("algorithm_name param was not set".to_string()))?)?; //PROBABLY NO COMPRESS

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

impl fmt::Display for TSigRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {}", format!("{}.", self.algorithm_name.as_ref().unwrap()),
               self.time_signed,
               self.fudge,
               hex::encode(&self.mac),
               self.original_id,
               self.error,
               hex::encode(&self.data))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x8, 0x67, 0x73, 0x73, 0x2d, 0x74, 0x73, 0x69, 0x67, 0x0, 0x0, 0x0, 0x50, 0xf8, 0xcf, 0xbb, 0x8c, 0xa0, 0x0, 0x1c, 0x4, 0x4, 0x5, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x73, 0x28, 0x5d, 0xa, 0x2d, 0xf4, 0xa3, 0x34, 0x2f, 0xcf, 0x1, 0x6f, 0x3c, 0x9f, 0x76, 0x82, 0x2, 0x34, 0x0, 0x0, 0x0, 0x0 ];
    let record = TSigRRData::from_bytes(&buf, 0, buf.len()).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
