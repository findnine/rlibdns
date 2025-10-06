use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_record::ZoneRecord;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct SoaRecord {
    fqdn: Option<String>,
    mailbox: Option<String>,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum_ttl: u32
}

impl Default for SoaRecord {

    fn default() -> Self {
        Self {
            fqdn: None,
            mailbox: None,
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum_ttl: 0
        }
    }
}

impl RecordBase for SoaRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let length = u16::from_be_bytes([buf[off], buf[off+1]]);
        if length == 0 {
            return Ok(Default::default());
        }

        let (fqdn, data_length) = unpack_fqdn(buf, off+2);
        let mut off = off+data_length+2;

        let (mailbox, data_length) = unpack_fqdn(buf, off);
        off += data_length;

        let serial = u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        let refresh = u32::from_be_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);
        let retry = u32::from_be_bytes([buf[off+8], buf[off+9], buf[off+10], buf[off+11]]);
        let expire = u32::from_be_bytes([buf[off+12], buf[off+13], buf[off+14], buf[off+15]]);
        let minimum_ttl = u32::from_be_bytes([buf[off+16], buf[off+17], buf[off+18], buf[off+19]]);

        Ok(Self {
            fqdn: Some(fqdn),
            mailbox: Some(mailbox),
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl
        })
    }

    fn to_bytes(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RecordError> {
        let mut off = off;

        let mut buf = vec![0u8; 2];

        let fqdn = pack_fqdn(self.fqdn.as_ref().unwrap().as_str(), compression_data, off+2, true);
        buf.extend_from_slice(&fqdn);

        off += fqdn.len()+8;

        let mailbox = pack_fqdn(self.mailbox.as_ref().unwrap().as_str(), compression_data, off, true);
        buf.extend_from_slice(&mailbox);

        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.refresh.to_be_bytes());
        buf.extend_from_slice(&self.retry.to_be_bytes());
        buf.extend_from_slice(&self.expire.to_be_bytes());
        buf.extend_from_slice(&self.minimum_ttl.to_be_bytes());

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Soa
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

impl SoaRecord {

    pub fn new(fqdn: &str, mailbox: &str, serial: u32, refresh: u32, retry: u32, expire: u32, minimum_ttl: u32) -> Self {
        Self {
            fqdn: Some(fqdn.to_string()),
            mailbox: Some(mailbox.to_string()),
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl
        }
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = Some(fqdn.to_string());
    }

    pub fn get_fqdn(&self) -> Option<&String> {
        self.fqdn.as_ref()
    }

    pub fn set_mailbox(&mut self, mailbox: &str) {
        self.mailbox = Some(mailbox.to_string());
    }

    pub fn get_mailbox(&self) -> Option<&String> {
        self.mailbox.as_ref()
    }

    pub fn set_serial(&mut self, serial: u32) {
        self.serial = serial;
    }

    pub fn get_serial(&self) -> u32 {
        self.serial
    }

    pub fn set_refresh(&mut self, refresh: u32) {
        self.refresh = refresh;
    }

    pub fn get_refresh(&self) -> u32 {
        self.refresh
    }

    pub fn set_retry(&mut self, retry: u32) {
        self.retry = retry;
    }

    pub fn get_retry(&self) -> u32 {
        self.retry
    }

    pub fn set_expire(&mut self, expire: u32) {
        self.expire = expire;
    }

    pub fn get_expire(&self) -> u32 {
        self.expire
    }

    pub fn set_minimum_ttl(&mut self, minimum_ttl: u32) {
        self.minimum_ttl = minimum_ttl;
    }

    pub fn get_minimum_ttl(&self) -> u32 {
        self.minimum_ttl
    }
}

impl ZoneRecord for SoaRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        match index {
            0 => self.fqdn = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "fqdn param is not fully qualified (missing trailing dot)"))?.to_string()),
            1 => self.mailbox = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "mailbox param is not fully qualified (missing trailing dot)"))?.to_string()),
            2 => self.serial = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse serial param"))?,
            3 => self.refresh = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse refresh param"))?,
            4 => self.retry = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse retry param"))?,
            5 => self.expire = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse expire param"))?,
            6 => self.minimum_ttl = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse minimum_ttl param"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
        }

        Ok(())
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for SoaRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {} {} {} {} {}", self.get_type().to_string(),
               format!("{}.", self.fqdn.as_ref().unwrap_or(&String::new())),
               format!("{}.", self.mailbox.as_ref().unwrap_or(&String::new())),
               self.serial,
               self.refresh,
               self.retry,
               self.expire,
               self.minimum_ttl)
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x34, 0x3, 0x6e, 0x73, 0x31, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x5, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x9, 0x3a, 0x80, 0x0, 0x1, 0x51, 0x80, 0x0, 0x24, 0xea, 0x0, 0x0, 0x9, 0x3a, 0x80 ];
    let record = SoaRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
