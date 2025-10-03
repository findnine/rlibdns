use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::naptr_flags::NaptrFlags;
use crate::records::inter::record_base::{RecordBase, RecordError};

#[derive(Clone, Debug)]
pub struct NaptrRecord {
    pub(crate) order: u16,
    pub(crate) preference: u16,
    pub(crate) flags: Vec<NaptrFlags>,
    pub(crate) service: Option<String>,
    pub(crate) regex: Option<String>,
    pub(crate) replacement: Option<String>
}

impl Default for NaptrRecord {

    fn default() -> Self {
        Self {
            order: 0,
            preference: 0,
            flags: Vec::new(),
            service: None,
            regex: None,
            replacement: None
        }
    }
}

impl RecordBase for NaptrRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]);
        if length == 0 {
            return Ok(Default::default());
        }

        let order = u16::from_be_bytes([buf[off+2], buf[off+3]]);
        let preference = u16::from_be_bytes([buf[off+4], buf[off+5]]);

        let data_length = buf[off+6] as usize;
        let mut flags = Vec::new();

        for flag in String::from_utf8(buf[off + 7..off + 7 + data_length].to_vec())
                .map_err(|e| RecordError(e.to_string()))?.split(",") {
            let tok = flag.trim();
            if tok.is_empty() {
                continue;
            }

            flags.push(NaptrFlags::try_from(flag.chars()
                .next()
                .ok_or_else(|| RecordError("empty NAPTR flag token".to_string()))?).map_err(|e| RecordError(e.to_string()))?);
        }

        let mut off = off+7+data_length;

        let data_length = buf[off] as usize;
        let service = String::from_utf8(buf[off + 1..off + 1 + data_length].to_vec())
            .map_err(|e| RecordError(e.to_string()))?;

        off += 1+data_length;

        let data_length = buf[off] as usize;
        let regex = String::from_utf8(buf[off + 1..off + 1 + data_length].to_vec())
            .map_err(|e| RecordError(e.to_string()))?;

        off += 1+data_length;

        let data_length = buf[off] as usize;
        let replacement = String::from_utf8(buf[off + 1..off + 1 + data_length].to_vec())
            .map_err(|e| RecordError(e.to_string()))?;

        Ok(Self {
            order,
            preference,
            flags,
            service: Some(service),
            regex: Some(regex),
            replacement: Some(replacement)
        })
    }

    fn to_bytes(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 6];

        buf.splice(2..4, self.order.to_be_bytes());
        buf.splice(4..6, self.preference.to_be_bytes());

        let length = self.flags.len();
        buf.push(((length * 2) - 1) as u8);
        for (i, flag) in self.flags.iter().enumerate() {
            buf.push(flag.get_code());
            if i < length - 1 {
                buf.push(b',');
            }
        }

        let service = self.service.as_ref().ok_or_else(|| RecordError("service param was not set".to_string()))?.as_bytes();
        buf.push(service.len() as u8);
        buf.extend_from_slice(service);

        let regex = self.regex.as_ref().ok_or_else(|| RecordError("regex param was not set".to_string()))?.as_bytes();
        buf.push(regex.len() as u8);
        buf.extend_from_slice(regex);

        let replacement = self.replacement.as_ref().ok_or_else(|| RecordError("replacement param was not set".to_string()))?.as_bytes();
        buf.push(replacement.len() as u8);
        buf.extend_from_slice(replacement);

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Naptr
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

impl NaptrRecord {

    pub fn new(order: u16, preference: u16, flags: Vec<NaptrFlags>, service: &str, regex: &str, replacement: &str) -> Self {
        Self {
            order,
            preference,
            flags,
            service: Some(service.to_string()),
            regex: Some(regex.to_string()),
            replacement: Some(replacement.to_string())
        }
    }

    pub fn set_order(&mut self, order: u16) {
        self.order = order;
    }

    pub fn get_order(&self) -> u16 {
        self.order
    }

    pub fn set_preference(&mut self, preference: u16) {
        self.preference = preference;
    }

    pub fn get_preference(&self) -> u16 {
        self.preference
    }

    pub fn add_flags(&mut self, flags: NaptrFlags) {
        self.flags.push(flags);
    }

    pub fn get_flags(&self) -> &Vec<NaptrFlags> {
        self.flags.as_ref()
    }

    pub fn get_flags_mut(&mut self) -> &mut Vec<NaptrFlags> {
        self.flags.as_mut()
    }

    pub fn set_service(&mut self, service: &str) {
        self.service = Some(service.to_string());
    }

    pub fn get_service(&self) -> Option<String> {
        self.service.clone()
    }

    pub fn set_regex(&mut self, regex: &str) {
        self.regex = Some(regex.to_string());
    }

    pub fn get_regex(&self) -> Option<String> {
        self.regex.clone()
    }

    pub fn set_replacement(&mut self, replacement: &str) {
        self.replacement = Some(replacement.to_string());
    }

    pub fn get_replacement(&self) -> Option<String> {
        self.replacement.clone()
    }
}

impl fmt::Display for NaptrRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} \"{:?}\" \"{}\" \"{}\" {}", self.get_type().to_string(),
               self.order,
               self.preference,
               self.flags,
               self.service.as_ref().unwrap_or(&String::new()),
               self.regex.as_ref().unwrap_or(&String::new()),
               self.replacement.as_ref().unwrap_or(&String::new()))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x2b, 0x0, 0x64, 0x0, 0xa, 0x3, 0x55, 0x2c, 0x50, 0x7, 0x45, 0x32, 0x55, 0x2b, 0x73, 0x69, 0x70, 0x19, 0x21, 0x5e, 0x2e, 0x2a, 0x24, 0x21, 0x73, 0x69, 0x70, 0x3a, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x2e, 0x6e, 0x65, 0x74, 0x21, 0x0 ];
    let record = NaptrRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
