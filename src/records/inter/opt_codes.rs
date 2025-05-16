use std::{fmt, io};
use std::fmt::Formatter;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum OptCodes {
    Llq,
    Ul,
    Nsid,
    Dau,
    Dhu,
    N3u,
    Ecs,
    Expire,
    Cookie,
    TcpKeepalive,
    Padding,
    Chain,
    KeyTag,
    EdnsError,
    DnsSecTrustedKey,
    DnsSecValidated,
    AdaptiveDnsDiscovery,
    DoH,
    MultiUserClientSubnet
}

impl OptCodes {

    pub fn from_code(code: u16) ->  Option<Self> {
        for c in [
            Self::Llq,
            Self::Ul,
            Self::Nsid,
            Self::Dau,
            Self::Dhu,
            Self::N3u,
            Self::Ecs,
            Self::Expire,
            Self::Cookie,
            Self::TcpKeepalive,
            Self::Padding,
            Self::Chain,
            Self::KeyTag,
            Self::EdnsError,
            Self::DnsSecTrustedKey,
            Self::DnsSecValidated,
            Self::AdaptiveDnsDiscovery,
            Self::DoH,
            Self::MultiUserClientSubnet
        ] {
            if c.get_code() == code {
                return Some(c);
            }
        }

        None
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::Llq => 1,
            Self::Ul => 2,
            Self::Nsid => 3,
            Self::Dau => 5,
            Self::Dhu => 6,
            Self::N3u => 7,
            Self::Ecs => 8,
            Self::Expire => 9,
            Self::Cookie => 10,
            Self::TcpKeepalive => 11,
            Self::Padding => 12,
            Self::Chain => 13,
            Self::KeyTag => 14,
            Self::EdnsError => 15,
            Self::DnsSecTrustedKey => 17,
            Self::DnsSecValidated => 18,
            Self::AdaptiveDnsDiscovery => 19,
            Self::DoH => 20,
            Self::MultiUserClientSubnet => 21
        }
    }
}

impl fmt::Display for OptCodes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Llq => "Long-Lived Queries",
            Self::Ul => "Update Leases",
            Self::Nsid => "Name Server Identifier",
            Self::Dau => "DNSSEC Algorithm Understood",
            Self::Dhu => "DS Hash Understood",
            Self::N3u => "NSEC3 Hash Understood",
            Self::Ecs => "EDNS Client Subnet",
            Self::Expire => "Expire",
            Self::Cookie => "Cookie",
            Self::TcpKeepalive => "TCP Keepalive",
            Self::Padding => "Padding",
            Self::Chain => "Chain",
            Self::KeyTag => "Key Tag",
            Self::EdnsError => "EDNS Version 1 Error",
            Self::DnsSecTrustedKey => "DNSSEC Trusted Key",
            Self::DnsSecValidated => "DNSSEC Validated",
            Self::AdaptiveDnsDiscovery => "Adaptive DNS Discovery",
            Self::DoH => "DNS over HTTPS",
            Self::MultiUserClientSubnet => "Multi-User Client Subnet"
        })
    }
}
