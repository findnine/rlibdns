use std::fmt;
use std::fmt::Formatter;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
pub enum SvcParamKeys {
    Mandatory,
    Alpn,
    NoDefaultAlpn,
    Port,
    Ipv4Hint,
    Ech,
    Ipv6Hint,
    Unknown(u16)
}

impl SvcParamKeys {

    pub fn from_code(code: u16) -> Self {
        match code {
            0 => Self::Mandatory,
            1 => Self::Alpn,
            2 => Self::NoDefaultAlpn,
            3 => Self::Port,
            4 => Self::Ipv4Hint,
            5 => Self::Ech,
            6 => Self::Ipv6Hint,
            x => Self::Unknown(x)
        }
    }

    pub fn get_code(self) -> u16 {
        match self {
            Self::Mandatory       => 0,
            Self::Alpn            => 1,
            Self::NoDefaultAlpn   => 2,
            Self::Port            => 3,
            Self::Ipv4Hint        => 4,
            Self::Ech             => 5,
            Self::Ipv6Hint        => 6,
            Self::Unknown(x) => x
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "mandatory" => Self::Mandatory,
            "alpn" => Self::Alpn,
            "no-default-alpn" => Self::NoDefaultAlpn,
            "port" => Self::Port,
            "ipv4hint" => Self::Ipv4Hint,
            "ech" => Self::Ech,
            "ipv6hint" => Self::Ipv6Hint,
            _ => return None
        })
    }
}

impl fmt::Display for SvcParamKeys {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Mandatory => "mandatory",
            Self::Alpn => "alpn",
            Self::NoDefaultAlpn => "no-default-alpn",
            Self::Port => "port",
            Self::Ipv4Hint => "ipv4hint",
            Self::Ech => "ech",
            Self::Ipv6Hint => "ipv6hint",
            _ => "unknown"
        })
    }
}
