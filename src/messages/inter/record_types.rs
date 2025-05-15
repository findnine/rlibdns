use std::{fmt, io};
use std::fmt::Formatter;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum RecordTypes {
    A,
    Aaaa,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Txt,
    Srv,
    Opt,
    Rrsig,
    Nsec,
    DnsKey,
    Https,
    Spf,
    Tsig,
    Any,
    Caa
}

impl RecordTypes {

    pub fn from_code(code: u16) -> Result<Self, String> {
        for c in [
            Self::A,
            Self::Aaaa,
            Self::Ns,
            Self::Cname,
            Self::Soa,
            Self::Ptr,
            Self::Mx,
            Self::Txt,
            Self::Srv,
            Self::Opt,
            Self::Rrsig,
            Self::Nsec,
            Self::DnsKey,
            Self::Https,
            Self::Spf,
            Self::Tsig,
            Self::Any,
            Self::Caa
        ] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(format!("Couldn't find for code: {}", code))
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Srv => 33,
            Self::Opt => 41,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::DnsKey => 48,
            Self::Https => 65,
            Self::Spf => 99,
            Self::Tsig => 250,
            Self::Any => 255,
            Self::Caa => 257
        }
    }

    pub fn from_string(value: &str) -> io::Result<Self> {
        for c in [
            Self::A,
            Self::Aaaa,
            Self::Ns,
            Self::Cname,
            Self::Soa,
            Self::Ptr,
            Self::Mx,
            Self::Txt,
            Self::Srv,
            Self::Opt,
            Self::Rrsig,
            Self::Nsec,
            Self::DnsKey,
            Self::Https,
            Self::Spf,
            Self::Tsig,
            Self::Any,
            Self::Caa
        ] {
            if c.to_string() == value {
                return Ok(c);
            }
        }

        Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Couldn't find for value: {}", value)))
    }
}

impl fmt::Display for RecordTypes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Ns => "NS",
            Self::Cname => "CNAME",
            Self::Soa => "SOA",
            Self::Ptr => "PTR",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Srv => "SRV",
            Self::Opt => "OPT",
            Self::Rrsig => "RRSIG",
            Self::Nsec => "NSEC",
            Self::DnsKey => "DNSKEY",
            Self::Https => "HTTPS",
            Self::Spf => "SPF",
            Self::Tsig => "TSIG",
            Self::Any => "ANY",
            Self::Caa => "CAA"
        })
    }
}
