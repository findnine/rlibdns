use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::svc_param_keys::SvcParamKeys;
use crate::records::inter::record_base::RecordBase;
use crate::utils::base64;
use crate::utils::domain_utils::{pack_domain, unpack_domain};
use crate::utils::ordered_map::OrderedMap;

#[derive(Clone, Debug)]
pub struct SvcbRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) priority: u16,
    pub(crate) target: Option<String>,
    pub(crate) params: OrderedMap<SvcParamKeys, Vec<u8>>
}

impl Default for SvcbRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            priority: 0,
            target: None,
            params: OrderedMap::new()
        }
    }
}

impl RecordBase for SvcbRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let priority = u16::from_be_bytes([buf[off+8], buf[off+9]]);

        let (target, length) = unpack_domain(&buf, off+10);

        let length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += length+10;

        let mut params = OrderedMap::new();
        while off < length {
            let key = SvcParamKeys::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            params.insert(key, buf[off + 4..off + 4 + length].to_vec());
            off += length+4;
        }

        Self {
            class,
            ttl,
            priority,
            target: Some(target),
            params
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 12];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.class.get_code().to_be_bytes());
        buf.splice(4..8, self.ttl.to_be_bytes());

        buf.splice(10..12, self.priority.to_be_bytes());

        buf.extend_from_slice(&pack_domain(self.target.as_ref().unwrap().as_str(), label_map, off+12, true));

        for (key, value) in self.params.iter() {
            buf.extend_from_slice(&key.get_code().to_be_bytes());
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(&value);
        }

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Svcb
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

impl SvcbRecord {

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

impl fmt::Display for SvcbRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut output = Vec::new();

        for (key, value) in self.params.iter() {
            let formatted = match key {
                SvcParamKeys::Alpn => {
                    let mut parts = Vec::new();
                    let mut i = 0;
                    while i < value.len() {
                        let len = value[i] as usize;
                        i += 1;
                        if i + len <= value.len() {
                            let part = String::from_utf8_lossy(&value[i..i + len]);
                            parts.push(part.into_owned());
                            i += len;
                        } else {
                            break;
                        }
                    }
                    format!("{}=\"{}\"", key, parts.join(","))
                }
                SvcParamKeys::Ipv4Hint => {
                    let ips = value
                        .chunks_exact(4)
                        .map(|chunk| {
                            std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]).to_string()
                        })
                        .collect::<Vec<_>>();
                    format!("{}={}", key, ips.join(","))
                }
                SvcParamKeys::Ech => {
                    format!("{}={:x?}", key, base64::encode(value))
                }
                SvcParamKeys::Ipv6Hint => {
                    let ips = value
                        .chunks_exact(16)
                        .map(|chunk| {
                            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(chunk).unwrap()).to_string()
                        })
                        .collect::<Vec<_>>();
                    format!("{}={}", key, ips.join(","))
                }
                _ => format!("{}={:x?}", key, value),
            };

            output.push(formatted);
        }


        write!(f, "{:<8}{:<8}{:<8}{} {} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.priority,
               format!("{}.", self.target.as_ref().unwrap()),
               output.join(" "))
    }
}
