use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Copy, Default, Clone, Eq, PartialEq, Hash, Debug)]
pub enum OpCodes {
    #[default]
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Dso
}

impl OpCodes {

    pub fn get_code(&self) -> u8 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Dso => 6
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum OpCodeParseError {
    UnknownCode(u8),
    UnknownName(String)
}

impl TryFrom<u8> for OpCodes {

    type Error = OpCodeParseError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            3 => Self::Notify,
            4 => Self::Update,
            5 => Self::Dso,
            _  => return Err(OpCodeParseError::UnknownCode(v)),
        })
    }
}

impl FromStr for OpCodes {

    type Err = OpCodeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "QUERY" => Self::Query,
            "IQUERY" => Self::IQuery,
            "STATUS" => Self::Status,
            "NOTIFY" => Self::Notify,
            "UPDATE" => Self::Update,
            "DSO" => Self::Dso,
            _  => return Err(OpCodeParseError::UnknownName(s.to_string())),
        })
    }
}

impl fmt::Display for OpCodes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Query => "QUERY",
            Self::IQuery => "IQUERY",
            Self::Status => "STATUS",
            Self::Notify => "NOTIFY",
            Self::Update => "UPDATE",
            Self::Dso => "DSO"
        })
    }
}
