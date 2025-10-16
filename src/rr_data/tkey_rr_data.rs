use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::base64;
use crate::utils::fqdn_utils::{pack_fqdn, pack_fqdn_compressed, unpack_fqdn};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TKeyRRData {
    class: RRClasses,
    ttl: u32,
    algorithm_name: Option<String>,
    inception: u32,
    expiration: u32,
    mode: u16, //ENUM PLEASE
    error: u16,
    key: Vec<u8>,
    data: Vec<u8>
}

impl Default for TKeyRRData {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            algorithm_name: None,
            inception: 0,
            expiration: 0,
            mode: 0,
            error: 0,
            key: Vec::new(),
            data: Vec::new()
        }
    }
}

impl RRData for TKeyRRData {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let mut off = off;

        let class = RRClasses::try_from(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let (algorithm_name, algorithm_name_length) = unpack_fqdn(buf, off+8);
        off += 8+algorithm_name_length;

        let inception = u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        let expiration = u32::from_be_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);

        let mode = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        let error = u16::from_be_bytes([buf[off+10], buf[off+11]]);

        let key_length = 14+u16::from_be_bytes([buf[off+12], buf[off+13]]) as usize;
        let key = buf[off + 14.. off + key_length].to_vec();
        off += key_length;

        let data_length = off+2+u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        let data = buf[off + 2..data_length].to_vec();

        Ok(Self {
            class,
            ttl,
            algorithm_name: Some(algorithm_name),
            inception,
            expiration,
            mode,
            error,
            key,
            data
        })
    }

    fn to_wire(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 8]; //160

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn_compressed(self.algorithm_name.as_ref()
            .ok_or_else(|| RRDataError("algorithm_name param was not set".to_string()))?, compression_data, off+8)); //PROBABLY NO COMPRESS

        buf.extend_from_slice(&self.inception.to_be_bytes());
        buf.extend_from_slice(&self.expiration.to_be_bytes());

        buf.extend_from_slice(&self.mode.to_be_bytes());
        buf.extend_from_slice(&self.error.to_be_bytes());

        buf.extend_from_slice(&(self.key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.key);

        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 8]; //160

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.algorithm_name.as_ref()
            .ok_or_else(|| RRDataError("algorithm_name param was not set".to_string()))?)); //PROBABLY NO COMPRESS

        buf.extend_from_slice(&self.inception.to_be_bytes());
        buf.extend_from_slice(&self.expiration.to_be_bytes());

        buf.extend_from_slice(&self.mode.to_be_bytes());
        buf.extend_from_slice(&self.error.to_be_bytes());

        buf.extend_from_slice(&(self.key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.key);

        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::TKey
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

impl TKeyRRData {

    pub fn new(ttl: u32, class: RRClasses) -> Self {
        Self {
            class,
            ttl,
            ..Self::default()
        }
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }
}

impl fmt::Display for TKeyRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} {} {} {} {} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               format!("{}.", self.algorithm_name.as_ref().unwrap()),
               self.inception,
               self.expiration,
               self.mode,
               self.error,
               base64::encode(&self.key),
               base64::encode(&self.data)) //IF EMPTY USE -
    }
}
