use std::fs::File;
use std::io;
use std::io::BufReader;
use crate::records::inter::record_base::RecordBase;

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

    pub fn iter(&mut self) -> JournalParserIter {
        JournalParserIter {
            parser: self
        }
    }
}

pub struct JournalParserIter<'a> {
    parser: &'a mut JournalParser
}

impl<'a> Iterator for JournalParserIter<'a> {

    type Item = (String, Box<dyn RecordBase>);

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}
