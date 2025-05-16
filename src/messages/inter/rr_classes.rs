use std::{fmt, io};
use std::fmt::Formatter;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum RRClasses {
    In,
    Cs,
    Ch,
    Hs
}

impl RRClasses {

    pub fn from_code(code: u16) -> Option<Self> {
        for c in [Self::In, Self::Cs, Self::Ch, Self::Hs] {
            if c.get_code() == code {
                return Some(c);
            }
        }

        None
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::In => 1,
            Self::Cs => 2,
            Self::Ch => 3,
            Self::Hs => 4
        }
    }

    pub fn from_abbreviation(value: &str) -> Option<Self> {
        for c in [Self::In, Self::Cs, Self::Ch, Self::Hs] {
            if c.to_abbreviation() == value {
                return Some(c);
            }
        }

        None
    }

    pub fn to_abbreviation(&self) -> String {
        match self {
            Self::In => "IN",
            Self::Cs => "CS",
            Self::Ch => "CH",
            Self::Hs => "HS"
        }.to_string()
    }
}

impl fmt::Display for RRClasses {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::In => "Internet",
            Self::Cs => "Unasigned",
            Self::Ch => "Chaos",
            Self::Hs => "Hesiod"
        })
    }
}
