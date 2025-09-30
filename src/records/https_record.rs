use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::records::inter::svc_param::SvcParams;
use crate::records::inter::svc_param_keys::SvcParamKeys;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Clone, Debug)]
pub struct HttpsRecord {
    pub(crate) priority: u16,
    pub(crate) target: Option<String>,
    pub(crate) params: Vec<SvcParams>
}

impl Default for HttpsRecord {

    fn default() -> Self {
        Self {
            priority: 0,
            target: None,
            params: Vec::new()
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

        let mut params = Vec::new();
        while off < length {
            let key = SvcParamKeys::from_code(u16::from_be_bytes([buf[off], buf[off+1]]));
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            params.push(SvcParams::from_bytes(key, &buf[off+4..off+4+length]).unwrap());

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

        for param in self.params.iter() {
            buf.extend_from_slice(&param.get_code().to_be_bytes());
            let param_buf = param.to_bytes();
            buf.extend_from_slice(&(param_buf.len() as u16).to_be_bytes());
            buf.extend_from_slice(&param_buf);
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

    pub fn add_param(&mut self, param: SvcParams) {
        self.params.push(param);
    }

    pub fn get_params(&self) -> &Vec<SvcParams> {
        self.params.as_ref()
    }

    pub fn get_params_mut(&mut self) -> &mut Vec<SvcParams> {
        self.params.as_mut()
    }
}

impl fmt::Display for HttpsRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{} {} {}", self.get_type().to_string(),
               self.priority,
               format!("{}.", self.target.as_ref().unwrap()),
               self.params.iter()
                   .map(|s| s.to_string())
                   .collect::<Vec<_>>()
                   .join(" "))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x96, 0x0, 0x1, 0x3, 0x77, 0x77, 0x77, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x1, 0x0, 0x6, 0x2, 0x68, 0x33, 0x2, 0x68, 0x32, 0x0, 0x4, 0x0, 0x8, 0x68, 0x15, 0x2a, 0x89, 0xac, 0x43, 0xce, 0x1c, 0x0, 0x5, 0x0, 0x47, 0x0, 0x45, 0xfe, 0xd, 0x0, 0x41, 0xda, 0x0, 0x20, 0x0, 0x20, 0xad, 0xee, 0x8b, 0x18, 0xce, 0xda, 0xba, 0x2b, 0x15, 0xe4, 0x6e, 0x16, 0x57, 0xc1, 0xf4, 0x91, 0x27, 0x41, 0xc0, 0xd8, 0xbf, 0x6, 0x22, 0x55, 0xa1, 0xd6, 0x80, 0x27, 0x63, 0x7e, 0x4e, 0x10, 0x0, 0x4, 0x0, 0x1, 0x0, 0x1, 0x0, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x0, 0x6, 0x0, 0x20, 0x26, 0x6, 0x47, 0x0, 0x30, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68, 0x15, 0x2a, 0x89, 0x26, 0x6, 0x47, 0x0, 0x30, 0x35, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xac, 0x43, 0xce, 0x1c ];
    let record = HttpsRecord::from_bytes(&buf, 0);
    assert_eq!(buf, record.to_bytes(&mut HashMap::new(), 0).unwrap());
}
