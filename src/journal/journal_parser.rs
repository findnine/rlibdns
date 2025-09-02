use std::fs::File;
use std::io;
use std::io::BufReader;

pub struct JournalParser {
    reader: BufReader<File>
}

impl JournalParser {

    pub fn open(file_path: &str) -> io::Result<Self> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader
        })
    }
}
