use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::opt_codes::OptCodes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::hex;
use crate::utils::ordered_map::OrderedMap;

#[derive(Clone, Debug)]
pub struct OptRecord {
    payload_size: u16,
    ext_rcode: u8,
    edns_version: u8,
    flags: u16,
    options: OrderedMap<OptCodes, Vec<u8>>
}

impl Default for OptRecord {

    fn default() -> Self {
        Self {
            payload_size: 512,
            ext_rcode: 0,
            edns_version: 0,
            flags: 0x8000,
            options: OrderedMap::new()
        }
    }
}

impl RecordBase for OptRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let payload_size = u16::from_be_bytes([buf[off], buf[off+1]]);
        let ext_rcode = buf[off+2];
        let edns_version = buf[off+3];
        let flags = u16::from_be_bytes([buf[off+4], buf[off+5]]);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        let mut off = off+8;
        let mut options = OrderedMap::new();

        while off < data_length {
            let opt_code = OptCodes::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            options.insert(opt_code, buf[off + 4..off + 4 + length].to_vec());

            off += 4+length;
        }

        Self {
            payload_size,
            ext_rcode,
            edns_version,
            flags,
            options
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.get_type().get_code().to_be_bytes());
        buf.splice(2..4, self.payload_size.to_be_bytes());

        buf[4] = self.ext_rcode;
        buf[5] = self.edns_version;

        buf.splice(6..8, self.flags.to_be_bytes());

        for (code, option) in self.options.iter() {
            buf.extend_from_slice(&code.get_code().to_be_bytes());
            buf.extend_from_slice(&(option.len() as u16).to_be_bytes());
            buf.extend_from_slice(&option);
        }

        buf.splice(8..10, ((buf.len()-10) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Opt
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

impl OptRecord {

    pub fn new(payload_size: u16, ext_rcode: u8, edns_version: u8, flags: u16) -> Self {
        Self {
            payload_size,
            ext_rcode,
            edns_version,
            flags,
            options: OrderedMap::new()
        }
    }
}

impl fmt::Display for OptRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "\t\t\t\t\t\t{}\t\tUDPsize={}; ext-rcode {}; edns-version {}",
               self.get_type(),
               self.payload_size,
               self.ext_rcode,
               self.edns_version)?;

        if self.flags & 0x8000 != 0 {
            write!(f, "; flags: do")?;
        }

        if !self.options.is_empty() {
            write!(f, "; options:")?;

            for (code, option) in self.options.iter() {
                match code {
                    OptCodes::Ecs => {
                        if option.len() >= 4 {
                            let family = u16::from_be_bytes([option[0], option[1]]);
                            let src_prefix = option[2];
                            let scope_prefix = option[3];
                            let addr = &option[4..];

                            let ip_str = match family {
                                1 => format!("{}", Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
                                2 => format!("{}", Ipv6Addr::from(<[u8; 16]>::try_from(addr).unwrap_or_default())),
                                _ => format!("unknown family {}", family),
                            };

                            write!(f, " {code} {ip_str}/{src_prefix}/{scope_prefix}")?;

                        } else {
                            write!(f, " {code} (invalid)")?;
                        }
                    }
                    _ => write!(f, " {code} {}", hex::encode(option))?
                }
            }
        }

        Ok(())
    }
}
