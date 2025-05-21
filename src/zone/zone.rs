use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read};
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::zone::zone_parser2::{Record, RecordData};

#[derive(Debug, PartialEq, Eq)]
enum ParserState {
    Init,
    Common,
    Directive,
    Data,
    QString,
}

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

    pub fn from_file(file_path: &str, origin: &str) -> io::Result<Self> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);

        let mut records = Vec::new();

        let mut state = ParserState::Init;
        let mut paren_count = 0;

        for line in reader.lines() {

            for part in line?.as_bytes().split_inclusive(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'(' || b == b')') {
                println!("{}", String::from_utf8(part.to_vec()).unwrap());

                let part_len = part.len();
                let mut word_len = part_len;

                if part[0] == b';' && state != ParserState::QString {
                    continue;
                }

                match part[part_len - 1] {
                    b' ' | b'\t' | b'\n' => {
                        word_len -= 1;
                    }
                    b'(' => {
                        paren_count += 1;
                        word_len -= 1;
                    }
                    b')' => {
                        paren_count -= 1;
                        word_len -= 1;
                    }
                    _ => {}
                }

                if word_len == 0 && (part[0] == b'\n' || state != ParserState::Init) {
                    continue;
                }


                let mut class = RRClasses::In;

                match state {
                    ParserState::Init => {
                        let word = String::from_utf8(part[0..word_len].to_vec()).unwrap().to_lowercase();

                        if pos == 0 && paren_count == 0 {
                            if word.starts_with('$') {
                                self.directive_buf = word;
                                state = ParserState::Directive;

                            } else {
                                if word_len > 0 {
                                    self.name = word;
                                }

                                state = ParserState::Common;
                            }
                        }
                    }
                    ParserState::Common => {
                        let word = String::from_utf8(part[0..word_len].to_vec()).unwrap().to_uppercase();

                        if let Some(c) = RRClasses::from_abbreviation(&word) {
                            class = c;

                        } else if let Some(_type) = RRTypes::from_string(&word) {
                            self._type = _type;
                            self.state = ParserState::Data;
                            rec.insert(Record::new(&self.name, self.ttl, self.class, self._type));

                        } else {
                            self.ttl = word.parse().expect(&format!("Parse error on line {} pos {}", self.line_no, pos));
                        }
                    }
                    ParserState::Directive => {
                        let value = String::from_utf8(part[0..word_len].to_vec()).unwrap().to_uppercase();
/*
                        if self.directive_buf == "$ttl" {
                            self.default_ttl = value.parse().expect(&format!("Parse error on line {} pos {}", self.line_no, pos));

                        } else if self.directive_buf == "$origin" {
                            self.origin = value;

                        } else {
                            panic!("Unknown directive {}", self.directive_buf);
                        }
*/
                        state = ParserState::Init;
                    }
                    ParserState::Data => {
                        if part[0] == b'"' {
                            if part[word_len - 1] == b'"' {
                                //rec.as_mut().unwrap().push_data(RecordData::from_bytes(&part[1..word_len - 1]));

                            } else {
                                state = ParserState::QString;
                                //self.quoted_buf = format!("{}{}", String::from_utf8(part[1..word_len].to_vec()).unwrap(), part[word_len] as char);
                            }

                        } else {
                            //rec.as_mut().unwrap().push_data(RecordData::from_bytes(&part[0..word_len]));
                        }
                    }
                    ParserState::QString => {
                        if part[word_len - 1] == b'"' {
                            //PARSE THIS INTO THE ACTUAL RECORD DATA...

                            //let s = format!("{}", String::from_utf8(part[0..word_len - 1].to_vec()).unwrap());
                            //self.quoted_buf.push_str(&s);
                            //rec.as_mut().unwrap().push_data(RecordData::new(&self.quoted_buf));
                            state = ParserState::Data;

                        } else {
                            //self.quoted_buf.push_str(&format!("{}{}", String::from_utf8(part[0..word_len].to_vec()).unwrap(), part[word_len] as char));
                        }
                    }
                }

                pos += plen;

            }
        }

        Ok(Self {
            name: String::new(),
            records
        })
    }
}
