use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::utils::base64;
use crate::utils::time_utils::TimeUtils;
use crate::zone::inter::zone_record::ZoneRecord;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct RRSigRecord {
    type_covered: Option<RRTypes>,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: Option<String>,
    signature: Vec<u8>
}

impl Default for RRSigRecord {

    fn default() -> Self {
        Self {
            type_covered: None,
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
        let mut length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let type_covered = RRTypes::try_from(u16::from_be_bytes([buf[off+2], buf[off+3]]))
            .map_err(|e| RecordError(e.to_string()))?;

        let algorithm = buf[off+4];
        let labels = buf[off+5];

        let original_ttl = u32::from_be_bytes([buf[off+6], buf[off+7], buf[off+8], buf[off+9]]);
        let expiration = u32::from_be_bytes([buf[off+10], buf[off+11], buf[off+12], buf[off+13]]);
        let inception = u32::from_be_bytes([buf[off+14], buf[off+15], buf[off+16], buf[off+17]]);
        let key_tag = u16::from_be_bytes([buf[off+18], buf[off+19]]);

        let (signer_name, signer_name_length) = unpack_fqdn(buf, off+20);

        length += off+2;

        let signature = buf[off+20+signer_name_length..length].to_vec();

        Ok(Self {
            type_covered: Some(type_covered),
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
        let mut buf = vec![0u8; 20];

        buf.splice(2..4, self.type_covered.as_ref()
            .ok_or_else(|| RecordError("type_covered param was not set".to_string()))?.get_code().to_be_bytes());

        buf[4] = self.algorithm;
        buf[5] = self.labels;

        buf.splice(6..10, self.original_ttl.to_be_bytes());
        buf.splice(10..14, self.expiration.to_be_bytes());
        buf.splice(14..18, self.inception.to_be_bytes());
        buf.splice(18..20, self.key_tag.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.signer_name.as_ref()
            .ok_or_else(|| RecordError("signer_name param was not set".to_string()))?, compression_data, off+22, true));

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
            type_covered: Some(type_covered),
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
        self.type_covered = Some(type_covered);
    }

    pub fn get_type_covered(&self) -> Option<&RRTypes> {
        self.type_covered.as_ref()
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

impl ZoneRecord for RRSigRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.type_covered = Some(RRTypes::from_str(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse type_covered param for record type {}", self.get_type())))?),
            1 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse algorithm param for record type {}", self.get_type())))?,
            2 => self.labels = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse labels param for record type {}", self.get_type())))?,
            3 => self.original_ttl = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse original_ttl param for record type {}", self.get_type())))?,
            4 => self.expiration = u32::from_time_format(value),
            5 => self.inception = u32::from_time_format(value),
            6 => self.key_tag = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse key_tag param for record type {}", self.get_type())))?,
            7 => self.signer_name = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, &format!("signer_name param is not fully qualified (missing trailing dot) for record type {}", self.get_type())))?.to_string()),
            8 => self.signature = base64::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse signature param for record type {}", self.get_type())))?,
            _ => self.signature.extend_from_slice(&base64::decode(value).unwrap())
        })
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for RRSigRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {} {} {} {} {} {} {}", self.get_type().to_string(),
               self.type_covered.as_ref().map(|t| t.to_string()).unwrap_or(String::new()),
               self.algorithm,
               self.labels,
               self.original_ttl,
               self.expiration.to_time_format(),
               self.inception.to_time_format(),
               self.key_tag,
               format!("{}.", self.signer_name.as_ref().unwrap_or(&String::new())),
               base64::encode(&self.signature))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x5d, 0x0, 0x2f, 0xd, 0x2, 0x0, 0x0, 0x7, 0x8, 0x68, 0xe7, 0x3c, 0x8d, 0x68, 0xe4, 0x7d, 0x6d, 0x86, 0xc9, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xf4, 0xd0, 0x3b, 0x11, 0x97, 0x31, 0x45, 0x12, 0x23, 0x4c, 0x45, 0x1a, 0xef, 0x28, 0xc0, 0x3c, 0xf7, 0xfc, 0x1b, 0x6b, 0xa7, 0x21, 0x1f, 0xe1, 0xc9, 0xb, 0x2f, 0x76, 0xc7, 0xb8, 0x52, 0x9, 0x83, 0x96, 0xbc, 0x69, 0x10, 0x43, 0x73, 0xe, 0x5c, 0x1, 0xf4, 0x78, 0x4e, 0x49, 0x86, 0xe7, 0xdf, 0xf6, 0xa, 0xa3, 0x1a, 0x75, 0xc2, 0x27, 0x53, 0xfb, 0x59, 0x52, 0x99, 0xb1, 0x44, 0xff ];
    let record = RRSigRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
