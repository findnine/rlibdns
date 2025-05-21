use std::fs::File;
use std::io;
use std::io::{BufReader, Read};
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
        let mut reader = BufReader::new(file);

        let mut buf = [0u8; 1];
        let mut records = Vec::new();

        let mut paren_depth = 0;

        for byte in reader.bytes() {

            match byte? {
                b'\n' => {
                    if paren_depth == 0 {
                        // End of logical line
                        //if !logical_line.is_empty() {
                        //    let line_str = String::from_utf8_lossy(&logical_line);
                        //    println!("Logical line: {}", line_str);
                        //    //logical_line.clear();
                        //}
                    } else {
                        //logical_line.push(b' '); // Replace newline with space inside multiline
                    }
                }
                b'(' => {
                    paren_depth += 1;
                    //logical_line.push(byte);
                }
                b')' => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    }
                    //logical_line.push(byte);
                }
                _ => {
                    //logical_line.push(byte);
                }
            }
        }

        Ok(Self {
            name: String::new(),
            records
        })
    }
}
