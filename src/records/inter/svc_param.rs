use std::fmt;
use std::fmt::Formatter;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::utils::{base64, hex};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum SvcParam {
    Mandatory(Vec<u16>),
    Alpn(Vec<Vec<u8>>),
    NoDefaultAlpn,
    Port(u16),
    Ipv4Hint(Vec<Ipv4Addr>),
    Ech(Vec<u8>),
    Ipv6Hint(u16, Vec<u8>)
}

impl SvcParam {

    pub fn from_bytes(code: u16, buf: &[u8]) -> Option<Self> {
        Some(match code {
            0 => SvcParam::Mandatory(buf
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect()),
            1 => {
                let mut ids = Vec::new();
                let mut off = 0;
                while off < buf.len() {
                    let len = buf[off] as usize;
                    off += 1;
                    let end = off + len;
                    ids.push(buf[off..end].to_vec());
                    off = end;
                }
                SvcParam::Alpn(ids)
            }
            2 => Self::NoDefaultAlpn,
            3 => SvcParam::Port(u16::from_be_bytes([buf[0], buf[1]])),
            4 => SvcParam::Ipv4Hint(buf.chunks_exact(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect()),
            5 => SvcParam::Ech(buf.to_vec()),
            6 => SvcParam::Ipv6Hint((buf.len() / 16) as u16, buf.to_vec()),
            _ => return None
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SvcParam::Mandatory(list) => {
                let mut out = Vec::with_capacity(list.len() * 2);
                for v in list {
                    out.extend_from_slice(&v.to_be_bytes());
                }
                out
            }
            SvcParam::Alpn(ids) => {
                let mut out = Vec::new();
                for id in ids {
                    out.push(id.len() as u8);
                    out.extend_from_slice(id);
                }
                out
            }
            SvcParam::NoDefaultAlpn => {
                Vec::new() // always empty
            }
            SvcParam::Port(port) => port.to_be_bytes().to_vec(),
            SvcParam::Ipv4Hint(addrs) => {
                let mut out = Vec::with_capacity(addrs.len() * 4);
                for ip in addrs {
                    out.extend_from_slice(&ip.octets());
                }
                out
            }
            SvcParam::Ech(data) => data.clone(),
            SvcParam::Ipv6Hint(_count, raw) => {
                raw.clone()
            }
        }
    }

    pub fn get_code(&self) -> u16 {
        match self {
            SvcParam::Mandatory(_)    => 0,
            SvcParam::Alpn(_)         => 1,
            SvcParam::NoDefaultAlpn   => 2,
            SvcParam::Port(_)         => 3,
            SvcParam::Ipv4Hint(_)     => 4,
            SvcParam::Ech(_)          => 5,
            SvcParam::Ipv6Hint(_, _)  => 6
        }
    }
}

impl fmt::Display for SvcParam {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SvcParam::Mandatory(list) => {
                write!(f, "mandatory=")?;
                let mut first = true;
                for v in list {
                    if !first {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", v)?;
                    first = false;
                }
                Ok(())
            }
            SvcParam::Alpn(ids) => {
                let mut alpn_strs = Vec::new();

                for id in ids {
                    if let Ok(s) = std::str::from_utf8(id) {
                        alpn_strs.push(s.to_string());
                    } else {
                        alpn_strs.push(hex::encode(id));
                    }
                }
                write!(f, "alpn=\"{}\"", alpn_strs.join(","))
            }
            SvcParam::NoDefaultAlpn => write!(f, "no-default-alpn"),
            SvcParam::Port(p) => write!(f, "port={}", p),
            SvcParam::Ipv4Hint(addrs) => {
                let ips: Vec<String> = addrs.iter().map(|ip| ip.to_string()).collect();
                write!(f, "ipv4hint={}", ips.join(","))
            }
            SvcParam::Ech(data) => write!(f, "ech={}", base64::encode(data)),
            SvcParam::Ipv6Hint(_, raw) => {
                if raw.len() % 16 == 0 {
                    let mut ips = Vec::new();
                    for chunk in raw.chunks_exact(16) {
                        let arr: [u8; 16] = chunk.try_into().unwrap();
                        ips.push(Ipv6Addr::from(arr).to_string());
                    }
                    return write!(f, "ipv6hint={}", ips.join(","));
                }

                write!(f, "ipv6hint={}", hex::encode(raw))
            }
        }
    }
}
