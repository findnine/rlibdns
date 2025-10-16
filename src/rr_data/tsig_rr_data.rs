use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
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

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let mut off = off;

        //let class = RRClasses::try_from(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        //let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        //let length = u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;

        let (algorithm_name, algorithm_name_length) = unpack_fqdn(buf, off+2);
        off += 2+algorithm_name_length;

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
        let data = buf[off + 6..data_length].to_vec();

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

    fn to_wire(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 2]; //160

        buf.extend_from_slice(&pack_fqdn_compressed(self.algorithm_name.as_ref()
            .ok_or_else(|| RRDataError("algorithm_name param was not set".to_string()))?, compression_data, off+2)); //PROBABLY NO COMPRESS

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

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 2]; //160

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

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

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

    pub fn new(algorithm_name: &str, time_signed: u64, fudge: u16, mac: Vec<u8>, original_id: u16, error: u16, data: Vec<u8>) -> Self {
        Self {
            algorithm_name: Some(algorithm_name.to_string()),
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            data
        }
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
    let buf = vec![  ];
    let record = TSigRRData::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
