use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::svc_param_keys::SvcParamKeys;
use crate::records::inter::record_base::RecordBase;
use crate::utils::base64;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::utils::index_map::IndexMap;

#[derive(Clone, Debug)]
pub struct HttpsRecord {
    pub(crate) priority: u16,
    pub(crate) target: Option<String>,
    pub(crate) params: IndexMap<SvcParamKeys, Vec<u8>>
}

impl Default for HttpsRecord {

    fn default() -> Self {
        Self {
            priority: 0,
            target: None,
            params: IndexMap::new()
        }
    }
}

impl RecordBase for HttpsRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let priority = u16::from_be_bytes([buf[off+2], buf[off+3]]);

        let (target, target_length) = unpack_fqdn(&buf, off+4);

        let length = off+2+u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        off += 4+target_length;

        let mut params = IndexMap::new();
        while off < length {
            let key = SvcParamKeys::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            params.insert(key, buf[off + 4..off + 4 + length].to_vec());
            off += length+4;
        }

        Self {
            priority,
            target: Some(target),
            params
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 4];

        buf.splice(2..4, self.priority.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.target.as_ref().unwrap().as_str(), label_map, off+4, true));

        for (key, value) in self.params.iter() {
            buf.extend_from_slice(&key.get_code().to_be_bytes());
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(&value);
        }

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Https
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

impl HttpsRecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
        }
    }

    pub fn set_priority(&mut self, priority: u16) {
        self.priority = priority;
    }

    pub fn get_priority(&self) -> u16 {
        self.priority
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn get_target(&self) -> Option<String> {
        self.target.clone()
    }

    pub fn has_param(&self, key: &SvcParamKeys) -> bool {
        self.params.contains_key(key)
    }

    pub fn insert_param(&mut self, key: SvcParamKeys, param: Vec<u8>) {
        self.params.insert(key, param);
    }

    pub fn get_param(&self, key: &SvcParamKeys) -> Option<&Vec<u8>> {
        self.params.get(key)
    }

    pub fn get_param_mut(&mut self, key: &SvcParamKeys) -> Option<&mut Vec<u8>> {
        self.params.get_mut(key)
    }

    pub fn get_params(&self) -> &IndexMap<SvcParamKeys, Vec<u8>> {
        self.params.as_ref()
    }

    pub fn get_params_mut(&mut self) -> &mut IndexMap<SvcParamKeys, Vec<u8>> {
        self.params.as_mut()
    }
}

impl fmt::Display for HttpsRecord {

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


        write!(f, "{:<8}{} {} {}", self.get_type().to_string(),
               self.priority,
               format!("{}.", self.target.as_ref().unwrap()),
               output.join(" "))
    }
}
