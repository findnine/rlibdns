use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::naptr_flags::NaptrFlags;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, pack_fqdn_compressed, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct NaptrRRData {
    order: u16,
    preference: u16,
    flags: Vec<NaptrFlags>,
    service: Option<String>,
    regex: Option<String>,
    replacement: Option<String>
}

impl Default for NaptrRRData {

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

impl RRData for NaptrRRData {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RRDataError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]);
        if length == 0 {
            return Ok(Default::default());
        }

        let order = u16::from_be_bytes([buf[off+2], buf[off+3]]);
        let preference = u16::from_be_bytes([buf[off+4], buf[off+5]]);

        let data_length = buf[off+6] as usize;
        let mut flags = Vec::new();

        for flag in String::from_utf8(buf[off + 7..off + 7 + data_length].to_vec())
                .map_err(|e| RRDataError(e.to_string()))?.split(",") {
            let tok = flag.trim();
            if tok.is_empty() {
                continue;
            }

            flags.push(NaptrFlags::try_from(flag.chars()
                .next()
                .ok_or_else(|| RRDataError("empty NAPTR flag token".to_string()))?).map_err(|e| RRDataError(e.to_string()))?);
        }

        let mut off = off+7+data_length;

        let data_length = buf[off] as usize;
        let service = String::from_utf8(buf[off + 1..off + 1 + data_length].to_vec())
            .map_err(|e| RRDataError(e.to_string()))?;

        off += 1+data_length;

        let data_length = buf[off] as usize;
        let regex = String::from_utf8(buf[off + 1..off + 1 + data_length].to_vec())
            .map_err(|e| RRDataError(e.to_string()))?;

        off += 1+data_length;

        let (replacement, _) = unpack_fqdn(buf, off);

        Ok(Self {
            order,
            preference,
            flags,
            service: Some(service),
            regex: Some(regex),
            replacement: Some(replacement)
        })
    }

    fn to_bytes_compressed(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
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

        let service = self.service.as_ref().ok_or_else(|| RRDataError("service param was not set".to_string()))?.as_bytes();
        buf.push(service.len() as u8);
        buf.extend_from_slice(service);

        let regex = self.regex.as_ref().ok_or_else(|| RRDataError("regex param was not set".to_string()))?.as_bytes();
        buf.push(regex.len() as u8);
        buf.extend_from_slice(regex);

        buf.extend_from_slice(&pack_fqdn(self.replacement.as_ref()
            .ok_or_else(|| RRDataError("replacement param was not set".to_string()))?));

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Naptr
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
}

impl NaptrRRData {

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

    pub fn get_service(&self) -> Option<&String> {
        self.service.as_ref()
    }

    pub fn set_regex(&mut self, regex: &str) {
        self.regex = Some(regex.to_string());
    }

    pub fn get_regex(&self) -> Option<&String> {
        self.regex.as_ref()
    }

    pub fn set_replacement(&mut self, replacement: &str) {
        self.replacement = Some(replacement.to_string());
    }

    pub fn get_replacement(&self) -> Option<&String> {
        self.replacement.as_ref()
    }
}

impl ZoneRRData for NaptrRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.order = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse order param for record type {}", self.get_type())))?,
            1 => self.preference = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse preference param for record type {}", self.get_type())))?,
            2 => {
                let mut flags = Vec::new();

                for flag in value.split(",") {
                    let tok = flag.trim();
                    if tok.is_empty() {
                        continue;
                    }

                    flags.push(NaptrFlags::try_from(flag.chars()
                        .next()
                        .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, &format!("empty NAPTR flag token for record type {}", self.get_type())))?)
                        .map_err(|e|ZoneReaderError::new(ErrorKind::FormErr, &e.to_string()))?);
                }

                self.flags = flags;
            }
            3 => self.service = Some(value.to_string()),
            4 => self.regex = Some(value.to_string()),
            5 => self.replacement = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, &format!("replacement param is not fully qualified (missing trailing dot) for record type {}", self.get_type())))?.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for NaptrRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} \"{}\" \"{}\" \"{}\" {}", self.get_type().to_string(),
               self.order,
               self.preference,
               self.flags.iter()
                   .map(|f| f.to_string())
                   .collect::<Vec<_>>()
                   .join(","),
               self.service.as_ref().unwrap_or(&String::new()),
               self.regex.as_ref().unwrap_or(&String::new()),
               format!("{}.", self.replacement.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x2b, 0x0, 0x64, 0x0, 0xa, 0x3, 0x55, 0x2c, 0x50, 0x7, 0x45, 0x32, 0x55, 0x2b, 0x73, 0x69, 0x70, 0x19, 0x21, 0x5e, 0x2e, 0x2a, 0x24, 0x21, 0x73, 0x69, 0x70, 0x3a, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x2e, 0x6e, 0x65, 0x74, 0x21, 0x0 ];
    let record = NaptrRRData::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
