use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::base64;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_record::ZoneRecord;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug)]
pub struct NSecRecord {
    fqdn: Option<String>,
    _types: Vec<RRTypes>
}

impl Default for NSecRecord {

    fn default() -> Self {
        Self {
            fqdn: None,
            _types: Vec::new()
        }
    }
}

impl RecordBase for NSecRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        let mut length = u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        if length == 0 {
            return Ok(Default::default());
        }

        let (fqdn, fqdn_length) = unpack_fqdn(buf, off+2);
        let mut off = fqdn_length+2;

        println!("{off}  {length}");

        let mut _types = Vec::new();

        while off < length {
            let window = buf[off];
            let length = buf[off + 1] as usize;

            if off+2+length > length {
                break;
            }

            let bitmap = &buf[off + 2..off + 2 + length];

            for (i, &byte) in bitmap.iter().enumerate() {
                for bit in 0..8 {
                    if byte & (1 << (7 - bit)) != 0 {
                        let _type = RRTypes::try_from((window as u16) * 256 + (i as u16 * 8 + bit as u16))
                            .map_err(|e| RecordError(e.to_string()))?;
                        println!("{_type:?}");
                        //_types.push(_type);
                    }
                }
            }

            println!("{off}");

            off += 2+length;
        }

        Ok(Self {
            fqdn: Some(fqdn),
            _types
        })
    }

    fn to_bytes(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RecordError> {
        let mut buf = vec![0u8; 2];

        buf.extend_from_slice(&pack_fqdn(self.fqdn.as_ref().unwrap().as_str(), compression_data, off+4, true));

        let mut windows: BTreeMap<u8, Vec<u8>> = BTreeMap::new();

        for _type in &self._types {
            let code = _type.get_code();
            let window = (code / 256) as u8;
            let offset = (code % 256) as usize;
            let byte_index = offset / 8;
            let bit_index = 7 - (offset % 8);

            windows.entry(window).or_insert_with(|| vec![0; 32])[byte_index] |= 1 << bit_index;
        }

        for (window, bitmap) in windows {
            if let Some(non_zero_pos) = bitmap.iter().rposition(|&x| x != 0) {
                let trimmed_bitmap = &bitmap[..=non_zero_pos];

                buf.push(window);
                buf.push(trimmed_bitmap.len() as u8);
                buf.extend_from_slice(trimmed_bitmap);
            }
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

    pub fn new(fqdn: &str, _types: Vec<RRTypes>) -> Self {
        Self {
            fqdn: Some(fqdn.to_string()),
            _types
        }
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = Some(fqdn.to_string());
    }

    pub fn get_fqdn(&self) -> Option<&String> {
        self.fqdn.as_ref()
    }

    pub fn add_type(&mut self, _type: RRTypes) {
        self._types.push(_type);
    }

    pub fn get_types(&self) -> &Vec<RRTypes> {
        self._types.as_ref()
    }

    pub fn get_types_mut(&mut self) -> &mut Vec<RRTypes> {
        self._types.as_mut()
    }
}

impl ZoneRecord for NSecRecord {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        match index {
            //0 => self.address = Some(value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, &format!("unable to parse address param for record type {}", self.get_type())))?),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, &format!("extra record data found for record type {}", self.get_type())))
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
               format!("{}.", self.fqdn.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x1b, 0x1, 0x0, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x9, 0x62, 0x5, 0x80, 0xc, 0x54, 0xb, 0x8d, 0x1c, 0xc0, 0x1, 0x1, 0xc0 ];
    let record = NSecRecord::from_bytes(&buf, 0).unwrap();
    println!("{:?}", record);

    //assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
