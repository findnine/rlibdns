use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_record::ZoneRecord;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct NSecRecord {
    next_domain: Option<String>,
    types: Vec<RRTypes>
}

impl Default for NSecRecord {

    fn default() -> Self {
        Self {
            next_domain: None,
            types: Vec::new()
        }
    }
}

impl RecordBase for NSecRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let mut length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let (next_domain, next_domain_length) = unpack_fqdn(buf, off+2);

        length += off+2;
        let mut off = off+2+next_domain_length;
        let mut types = Vec::new();

        while off < length {
            if off+2 > length {
                return Err(RecordError("truncated NSEC window header".to_string()));
            }

            let window = buf[off];
            let data_length = buf[off + 1] as usize;
            off += 2;

            if data_length == 0 || data_length > 32 {
                return Err(RecordError("invalid NSEC window length".to_string()));
            }

            if off + data_length > length {
                return Err(RecordError("truncated NSEC bitmap".to_string()));
            }

            for (i, &byte) in buf[off..off + data_length].iter().enumerate() {
                for bit in 0..8 {
                    if (byte & (1 << (7 - bit))) != 0 {
                        let _type = RRTypes::try_from((window as u16) * 256 + (i as u16 * 8 + bit as u16))
                            .map_err(|e| RecordError(e.to_string()))?;
                        types.push(_type);
                    }
                }
            }

            off += data_length;
        }

        Ok(Self {
            next_domain: Some(next_domain),
            types
        })
    }

    fn to_bytes(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 2];

        buf.extend_from_slice(&pack_fqdn(self.next_domain.as_ref().unwrap().as_str(), compression_data, off+2, true));

        let mut windows: Vec<Vec<u8>> = vec![Vec::new(); 256];

        for _type in self.types.iter() {
            let code = _type.get_code();
            let w = (code >> 8) as usize;
            let low = (code & 0xFF) as u8;
            let byte_i = (low >> 3) as usize;
            let bit_in_byte = 7 - (low & 0x07);

            let bm = &mut windows[w];
            if bm.len() <= byte_i {
                bm.resize(byte_i + 1, 0);
            }
            bm[byte_i] |= 1 << bit_in_byte;
        }


        for (win, bm) in windows.into_iter().enumerate() {
            let mut used = bm.len();
            while used > 0 && bm[used - 1] == 0 {
                used -= 1;
            }
            if used == 0 {
                continue;
            }

            buf.push(win as u8);
            buf.push(used as u8);
            buf.extend_from_slice(&bm[..used]);
        }

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::NSec
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

impl NSecRecord {

    pub fn new(next_domain: &str, types: Vec<RRTypes>) -> Self {
        Self {
            next_domain: Some(next_domain.to_string()),
            types
        }
    }

    pub fn set_next_domain(&mut self, next_domain: &str) {
        self.next_domain = Some(next_domain.to_string());
    }

    pub fn get_next_domain(&self) -> Option<&String> {
        self.next_domain.as_ref()
    }

    pub fn add_type(&mut self, _type: RRTypes) {
        self.types.push(_type);
    }

    pub fn get_types(&self) -> &Vec<RRTypes> {
        self.types.as_ref()
    }

    pub fn get_types_mut(&mut self) -> &mut Vec<RRTypes> {
        self.types.as_mut()
    }
}

impl ZoneRecord for NSecRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        match index {
            0 => self.next_domain = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, &format!("next_domain param is not fully qualified (missing trailing dot) for record type {}", self.get_type())))?.to_string()),
            _ => self.types.push(RRTypes::from_str(value)
                .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse rr_types param for record type {}", self.get_type())))?)
        }

        Ok(())
    }

    fn upcast(self) -> Box<dyn ZoneRecord> {
        Box::new(self)
    }
}

impl fmt::Display for NSecRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} ", self.get_type().to_string(),
               format!("{}.", self.next_domain.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x1b, 0x1, 0x0, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x9, 0x62, 0x5, 0x80, 0xc, 0x54, 0xb, 0x8d, 0x1c, 0xc0, 0x1, 0x1, 0xc0 ];
    let record = NSecRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
