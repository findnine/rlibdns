use std::fmt;
use std::fmt::Formatter;

#[derive(Copy, Default, Clone, Eq, PartialEq, Hash, Debug)]
pub enum RRClasses {
    #[default]
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

    pub fn from_str(value: &str) -> Option<Self> {
        for c in [Self::In, Self::Cs, Self::Ch, Self::Hs] {
            if c.to_string() == value {
                return Some(c);
            }
        }

        None
    }
}

impl fmt::Display for RRClasses {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::In => "IN",
            Self::Cs => "CS",
            Self::Ch => "CH",
            Self::Hs => "HS"
        })
    }
}
