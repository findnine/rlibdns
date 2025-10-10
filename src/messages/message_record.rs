use std::collections::HashMap;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::utils::fqdn_utils::{pack_fqdn_compressed, unpack_fqdn};

#[derive(Debug, Clone)]
pub struct MessageRecord {
    fqdn: String,
    class: RRClasses,
    _type: RRTypes,
    ttl: u32,
    data: Vec<u8>
}

impl MessageRecord {

    pub fn new(fqdn: &str, class: RRClasses, _type: RRTypes, ttl: u32, data: Vec<u8>) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            class,
            _type,
            ttl,
            data
        }
    }

    pub fn set_fqdn(mut self, fqdn: &str) {
        self.fqdn = fqdn.to_string();
    }

    pub fn get_fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn set_class(mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn set_ttl(mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_data(mut self, data: Vec<u8>) {
        self.data = data;
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    pub fn get_data_compressed(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> &[u8] {
        match self._type {
            RRTypes::A => {
                match self.class {
                    RRClasses::Ch => {
                        let (name, consumed) = unpack_fqdn(&self.data[2..], 0);
                        let compressed_name = pack_fqdn_compressed(&name, compression_data, 2+off);

                        let mut buf = Vec::with_capacity(self.data.len()+compressed_name.len()-consumed);
                        buf.extend_from_slice(&((buf.len()-2) as u16).to_be_bytes());
                        //buf.extend_from_slice(&self.data[2..]);
                        buf.extend_from_slice(&compressed_name);
                        buf.extend_from_slice(&self.data[2 + consumed..]);

                        &buf
                    }
                    _ => &self.data
                }
            }
            RRTypes::Ns | RRTypes::CName | RRTypes::Ptr | RRTypes::NSec | RRTypes::TKey | RRTypes::TSig => {
                let (name, consumed) = unpack_fqdn(&self.data[2..], 0);
                let compressed_name = pack_fqdn_compressed(&name, compression_data, 2+off);

                let mut buf = Vec::with_capacity(self.data.len()+compressed_name.len()-consumed);
                buf.extend_from_slice(&((buf.len()-2) as u16).to_be_bytes());
                //buf.extend_from_slice(&self.data[2..]);
                buf.extend_from_slice(&compressed_name);
                buf.extend_from_slice(&self.data[2 + consumed..]);

                &buf
            }
            RRTypes::Soa => {
                /*
                let (name, consumed) = unpack_fqdn(&self.data[2..], 0);
                let (mailbox, consumed) = unpack_fqdn(&self.data[2..], 0);

                let compressed_name = pack_fqdn_compressed(&name, compression_data, 2+off);

                let mut buf = Vec::with_capacity(self.data.len()+compressed_name.len()-consumed);
                buf.extend_from_slice(&((buf.len()-2) as u16).to_be_bytes());
                //buf.extend_from_slice(&self.data[2..]);
                buf.extend_from_slice(&compressed_name);
                buf.extend_from_slice(&self.data[2 + consumed..]);

                &buf
                */
            }
            RRTypes::Mx => {

            }
            RRTypes::Srv => {

            }
            RRTypes::RRSig => {

            }

            RRTypes::Svcb | RRTypes::Https => {

            }
            _ => &self.data
        }
    }
}
