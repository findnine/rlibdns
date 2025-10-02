use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::utils::base64;
use crate::utils::time_utils::TimeUtils;

#[derive(Clone, Debug)]
pub struct RRSigRecord {
    pub(crate) type_covered: RRTypes,
    pub(crate) algorithm: u8,
    pub(crate) labels: u8,
    pub(crate) original_ttl: u32,
    pub(crate) expiration: u32,
    pub(crate) inception: u32,
    pub(crate) key_tag: u16,
    pub(crate) signer_name: Option<String>,
    pub(crate) signature: Vec<u8>
}

impl Default for RRSigRecord {

    fn default() -> Self {
        Self {
            type_covered: RRTypes::default(),
            algorithm: 0,
            labels: 0,
            original_ttl: 0,
            expiration: 0,
            inception: 0,
            key_tag: 0,
            signer_name: None,
            signature: Vec::new()
        }
    }
}

impl RecordBase for RRSigRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let mut off = off;

        let type_covered = RRTypes::try_from(u16::from_be_bytes([buf[off+2], buf[off+3]]))
            .map_err(|e| RecordError(e.to_string()))?;

        let algorithm = buf[off+4];
        let labels = buf[off+5];

        let original_ttl = u32::from_be_bytes([buf[off+6], buf[off+7], buf[off+8], buf[off+9]]);
        let expiration = u32::from_be_bytes([buf[off+10], buf[off+11], buf[off+12], buf[off+13]]);
        let inception = u32::from_be_bytes([buf[off+14], buf[off+15], buf[off+16], buf[off+17]]);
        let key_tag = u16::from_be_bytes([buf[off+18], buf[off+19]]);

        let (signer_name, length) = unpack_fqdn(buf, off+20);

        let data_length = off+2+u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        off += length+20;

        let signature = buf[off..data_length].to_vec();

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name: Some(signer_name),
            signature
        })
    }

    fn to_bytes(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 26];

        buf.splice(2..4, self.type_covered.get_code().to_be_bytes());

        buf[4] = self.algorithm;
        buf[5] = self.labels;

        buf.splice(6..10, self.original_ttl.to_be_bytes());
        buf.splice(10..14, self.expiration.to_be_bytes());
        buf.splice(14..18, self.inception.to_be_bytes());
        buf.splice(18..20, self.key_tag.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.signer_name.as_ref()
            .ok_or_else(|| RecordError("signer_name param was not set".to_string()))?, compression_data, off+20, true));

        buf.extend_from_slice(&self.signature);

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::RRSig
    }

    fn upcast(self) -> Box<dyn RecordBase> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }
}

impl RRSigRecord {

    pub fn new(type_covered: RRTypes, algorithm: u8, labels: u8, original_ttl: u32, expiration: u32, inception: u32, key_tag: u16, signer_name: &str, signature: Vec<u8>) -> Self {
        Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name: Some(signer_name.to_string()),
            signature
        }
    }

    pub fn set_type_covered(&mut self, type_covered: RRTypes) {
        self.type_covered = type_covered;
    }

    pub fn get_type_covered(&self) -> RRTypes {
        self.type_covered
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn get_algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_labels(&mut self, labels: u8) {
        self.labels = labels;
    }

    pub fn get_labels(&self) -> u8 {
        self.labels
    }

    pub fn set_original_ttl(&mut self, original_ttl: u32) {
        self.original_ttl = original_ttl;
    }

    pub fn get_original_ttl(&self) -> u32 {
        self.original_ttl
    }

    pub fn set_expiration(&mut self, expiration: u32) {
        self.expiration = expiration;
    }

    pub fn get_expiration(&self) -> u32 {
        self.expiration
    }

    pub fn set_inception(&mut self, inception: u32) {
        self.inception = inception;
    }

    pub fn get_inception(&self) -> u32 {
        self.inception
    }

    pub fn set_key_tag(&mut self, key_tag: u16) {
        self.key_tag = key_tag;
    }

    pub fn get_key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn set_signer_name(&mut self, signer_name: &str) {
        self.signer_name = Some(signer_name.to_string());
    }

    pub fn get_signer_name(&self) -> Option<&String> {
        self.signer_name.as_ref()
    }

    pub fn set_signature(&mut self, signature: &[u8]) {
        self.signature = signature.to_vec();
    }

    pub fn get_signature(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

impl fmt::Display for RRSigRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {} {} {} {} {} {} {}", self.get_type().to_string(),
               self.type_covered.to_string(),
               self.algorithm,
               self.labels,
               self.original_ttl,
               self.expiration.to_time_format(),
               self.inception.to_time_format(),
               self.key_tag,
               format!("{}.", self.signer_name.as_ref().unwrap()),
               base64::encode(&self.signature))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x63, 0x0, 0x1, 0xd, 0x2, 0x0, 0x0, 0x1, 0x2c, 0x68, 0x5e, 0xd8, 0xde, 0x68, 0x5c, 0x19, 0xbe, 0x86, 0xc9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xb4, 0x43, 0x8e, 0xe4, 0xdc, 0xd0, 0x7c, 0x16, 0x19, 0x8b, 0xbc, 0x9b, 0x25, 0x97, 0x7c, 0xb7, 0xf1, 0xda, 0xa5, 0x7f, 0xe2, 0x51, 0x4f, 0xf0, 0x65, 0x13, 0xf6, 0x11, 0x19, 0xe7, 0xcb, 0x10, 0x86, 0x71, 0xa7, 0xcf, 0x12, 0x85, 0x2a, 0x50, 0x65, 0xa1, 0x22, 0x43, 0x55, 0x93, 0xeb, 0x3, 0x9a, 0x7c, 0x6a, 0x56, 0xdf, 0x21, 0x21, 0x79, 0xcc, 0x19, 0x8b, 0xdd, 0x36, 0x6d, 0xf2, 0x64 ];
    let record = RRSigRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
