use std::{fmt, io};
use std::fmt::Formatter;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum ResponseCodes {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NoTimp,
    Refused,
    YxDomain,
    XrrSet,
    NotAuth,
    NotZone
}

impl ResponseCodes {

    pub fn from_code(code: u8) -> io::Result<Self> {
        for c in [
            Self::NoError,
            Self::FormErr,
            Self::ServFail,
            Self::NxDomain,
            Self::NoTimp,
            Self::Refused,
            Self::YxDomain,
            Self::XrrSet,
            Self::NotAuth,
            Self::NotZone
        ] {
            if c.get_code() == code {
                return Ok(c);
            }
        }

        Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Couldn't find for code: {}", code)))
    }

    pub fn get_code(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NoTimp => 4,
            Self::Refused => 5,
            Self::YxDomain => 6,
            Self::XrrSet => 6,
            Self::NotAuth => 8,
            Self::NotZone => 9
        }
    }
}

impl fmt::Display for ResponseCodes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::NoError => "No Error",
            Self::FormErr => "Format Error",
            Self::ServFail => "Server Failure",
            Self::NxDomain => "Domain Not Found",
            Self::NoTimp => "Not Implemented",
            Self::Refused => "Refused",
            Self::YxDomain => "Name Should Not Exist",
            Self::XrrSet => "RRset Should Not Exist",
            Self::NotAuth => "Not Authoritative",
            Self::NotZone => "Name Not In Zone"
        })
    }
}
