use std::fs::File;
use std::io;
use std::io::Read;
use crate::records::inter::record_base::RecordBase;

pub struct Zone {
    name: String,
    records: Vec<Box<dyn RecordBase>>
}

impl Zone {

    pub fn new(name: String) -> Self {
        Self {
            name,
            records: Vec::new()
        }
    }

    pub fn from_file(file_path: &str) -> io::Result<Self> {
        let mut file = File::open(file_path)?;

        let mut buf = [0u8; 1];
        let mut records = Vec::new();

        while file.read(&mut buf)? != 0 {
            
            
        }

        Ok(Self {
            name: String::new(),
            records
        })
    }
}
