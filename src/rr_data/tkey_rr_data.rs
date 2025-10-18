use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::base64;
use crate::utils::fqdn_utils::{pack_fqdn, pack_fqdn_compressed, unpack_fqdn};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TKeyRRData {
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

    fn from_bytes(buf: &[u8], off: usize, _len: usize) -> Result<Self, RRDataError> {
        let mut off = off;

        let (algorithm_name, algorithm_name_length) = unpack_fqdn(buf, off);
        off += algorithm_name_length;

        let inception = u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        let expiration = u32::from_be_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);

        let mode = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        let error = u16::from_be_bytes([buf[off+10], buf[off+11]]);

        let key_length = 14+u16::from_be_bytes([buf[off+12], buf[off+13]]) as usize;
        let key = buf[off + 14.. off + key_length].to_vec();
        off += key_length;

        let data_length = off+2+u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        let data = buf[off+2..data_length].to_vec();

        Ok(Self {
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
        let mut buf = Vec::with_capacity(158);

        buf.extend_from_slice(&pack_fqdn_compressed(self.algorithm_name.as_ref()
            .ok_or_else(|| RRDataError("algorithm_name param was not set".to_string()))?, compression_data, off)); //PROBABLY NO COMPRESS

        buf.extend_from_slice(&self.inception.to_be_bytes());
        buf.extend_from_slice(&self.expiration.to_be_bytes());

        buf.extend_from_slice(&self.mode.to_be_bytes());
        buf.extend_from_slice(&self.error.to_be_bytes());

        buf.extend_from_slice(&(self.key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.key);

        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

        Ok(buf)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(158);

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

impl TKeyRRData {

    pub fn new(algorithm_name: &str, inception: u32, expiration: u32, mode: u16, error: u16, key: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            algorithm_name: Some(algorithm_name.to_string()),
            inception,
            expiration,
            mode,
            error,
            key,
            data
        }
    }

    pub fn set_algorithm_name(&mut self, algorithm_name: &str) {
        self.algorithm_name = Some(algorithm_name.to_string());
    }

    pub fn algorithm_name(&self) -> Option<&String> {
        self.algorithm_name.as_ref()
    }

    pub fn set_inception(&mut self, inception: u32) {
        self.inception = inception;
    }

    pub fn inception(&self) -> u32 {
        self.inception
    }

    pub fn set_expiration(&mut self, expiration: u32) {
        self.expiration = expiration;
    }

    pub fn expiration(&self) -> u32 {
        self.expiration
    }

    pub fn set_mode(&mut self, mode: u16) {
        self.mode = mode;
    }

    pub fn mode(&self) -> u16 {
        self.mode
    }

    pub fn set_error(&mut self, error: u16) {
        self.error = error;
    }

    pub fn error(&self) -> u16 {
        self.error
    }

    pub fn set_key(&mut self, key: &[u8]) {
        self.key = key.to_vec();
    }

    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl fmt::Display for TKeyRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {}", format!("{}.", self.algorithm_name.as_ref().unwrap()),
               self.inception,
               self.expiration,
               self.mode,
               self.error,
               base64::encode(&self.key),
               base64::encode(&self.data)) //IF EMPTY USE -
    }
}

#[test]
fn test() {
    let buf = vec![ 0x8, 0x67, 0x73, 0x73, 0x2d, 0x74, 0x73, 0x69, 0x67, 0x0, 0x50, 0xf8, 0xcf, 0xbb, 0x50, 0xfa, 0x21, 0x3b, 0x0, 0x3, 0x0, 0x0, 0x0, 0xba, 0xa1, 0x81, 0xb7, 0x30, 0x81, 0xb4, 0xa0, 0x3, 0xa, 0x1, 0x0, 0xa1, 0xb, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2, 0xa2, 0x81, 0x9f, 0x4, 0x81, 0x9c, 0x60, 0x81, 0x99, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x1, 0x2, 0x2, 0x2, 0x0, 0x6f, 0x81, 0x89, 0x30, 0x81, 0x86, 0xa0, 0x3, 0x2, 0x1, 0x5, 0xa1, 0x3, 0x2, 0x1, 0xf, 0xa2, 0x7a, 0x30, 0x78, 0xa0, 0x3, 0x2, 0x1, 0x12, 0xa2, 0x71, 0x4, 0x6f, 0x32, 0x94, 0x40, 0xf8, 0xae, 0xaa, 0xbd, 0xa2, 0x9e, 0x7e, 0x78, 0x1d, 0xf, 0xf0, 0x9b, 0xae, 0x14, 0x5c, 0x99, 0xc1, 0xdc, 0xb6, 0xc7, 0xa0, 0xbd, 0x7a, 0x83, 0xed, 0x18, 0xb, 0xf9, 0xea, 0xa0, 0x29, 0x1f, 0xe, 0x82, 0xd8, 0x2f, 0x1d, 0x59, 0xb9, 0xda, 0x97, 0x41, 0xf2, 0x7b, 0xab, 0xa2, 0xdb, 0x38, 0xe9, 0xcd, 0xfe, 0x27, 0xb3, 0xbf, 0x13, 0xa, 0xeb, 0xde, 0xa7, 0x7e, 0x55, 0x1a, 0x6c, 0xff, 0x2d, 0x64, 0xfb, 0xfc, 0x56, 0x52, 0xb5, 0xc8, 0x28, 0x7, 0x17, 0x6c, 0xe7, 0x57, 0xe5, 0xf5, 0xaa, 0xd5, 0x84, 0x18, 0x80, 0x21, 0xa1, 0xd9, 0xdd, 0x3, 0x82, 0xf1, 0xcf, 0x1b, 0xe6, 0x17, 0x97, 0xee, 0x2b, 0xdd, 0x27, 0x80, 0xea, 0x42, 0xde, 0xc8, 0x57, 0x8a, 0x0, 0x0 ];
    let record = TKeyRRData::from_bytes(&buf, 0, buf.len()).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
