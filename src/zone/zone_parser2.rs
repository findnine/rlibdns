use std::fs::File;
use std::io::{BufReader, BufRead};
use std::fmt::{Display, Debug, Formatter};
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;

#[derive(Debug, Clone)]
pub struct RecordData {
    data: String
}

impl RecordData {

    pub fn new(data: &str) -> Self {
        Self {
            data: data.to_string()
        }
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            data: String::from_utf8(data.to_vec()).unwrap()
        }
    }
}

impl PartialEq for RecordData {

    fn eq(&self, other: &RecordData) -> bool {
        self.data == other.data
    }
}

impl Display for RecordData {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.data)
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub ttl: u32,
    pub class: RRClasses,
    pub _type: RRTypes,
    pub data: Vec<RecordData>
}

impl PartialEq for Record {

    fn eq(&self, other: &Record) -> bool {
        if self.name != other.name ||
            self.ttl != other.ttl ||
            self.class != other.class ||
            self._type != other._type ||
            self.data.len() != other.data.len() {
            return false;
        }

        let n = self.data.len();
        for i in 0..n {
            if self.data[i] != other.data[i] {
                return false;
            }
        }

        true
    }
}

impl Display for Record {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {} {}", self.name, self.ttl, self.class, self._type)?;

        for d in &self.data {
            write!(f, " {}", d)?
        }

        Ok(())
    }
}

impl Record {

    pub fn new(name: &str, ttl: u32, class: RRClasses , _type: RRTypes) -> Self {
        Self {
            name: name.to_string(),
            ttl: ttl,
            class: class,
            _type: _type,
            data: Default::default(),
        }
    }

    pub fn push_data(&mut self, data: RecordData) {
        self.data.push(data)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
enum ParserState {
    #[default]
    Init,
    Common,
    Directive,
    Data,
    QString,
}

pub struct ZoneParser<'a> {
    bufreader: BufReader<&'a File>,
    line_no: usize,
    quoted_buf: String,
    directive_buf: String,
    name: String,
    origin: String,
    default_ttl: u32,
    ttl: u32,
    class: RRClasses,
    _type: RRTypes,
    b_count: u16,
    end_of_stream: bool,
    state: ParserState
}

impl<'a> ZoneParser<'a> {

    pub fn new(file: &'a File, origin: &str) -> Self {
        let buf = BufReader::new(file);

        let mut origin_muted = origin.to_string();
        if !origin_muted.ends_with('.') {
            origin_muted.push('.');
        }

        Self {
            bufreader: buf,
            line_no: 0,
            quoted_buf: String::new(),
            directive_buf: String::new(),
            name: String::new(),
            origin: origin_muted,
            default_ttl: 0,
            ttl: 0,
            class: RRClasses::In,
            _type: RRTypes::A,
            b_count: 0,
            end_of_stream: false,
            state: Default::default()
        }
    }

    pub fn parse(&mut self) {
        self.state = ParserState::Init;
        if self.default_ttl != 0 {
            self.ttl = self.default_ttl;
        }

        let mut rec: Option<Record> = None;

        while !self.end_of_stream {
            self.parse_line(&mut rec);

            if rec.is_some() && self.b_count == 0 {
                println!("{:?}", rec);

                self.state = ParserState::Init;
                if self.default_ttl != 0 {
                    self.ttl = self.default_ttl;
                }

                rec = None;
            }
        }
    }

    fn parse_line(&mut self, rec: &mut Option<Record>) {
        let mut line = String::new();
        let len = self.bufreader.read_line(&mut line).expect("Error reading zonefile");

        if len == 0 {
            self.end_of_stream = true;
            return;
        }

        let bytes = line.as_bytes();
        let mut pos = 0;
        self.line_no += 1;

        for part in bytes.split_inclusive(
            |&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'(' || b == b')') {
            let plen = part.len();
            let mut wlen = plen;

            if part[0] == b';' && self.state != ParserState::QString {
                return;
            }

            match part[plen - 1] {
                b' ' | b'\t' | b'\n' => {
                    wlen -= 1;
                }
                b'(' => {
                    self.b_count += 1;
                    wlen -= 1;
                }
                b')' => {
                    self.b_count -= 1;
                    wlen -= 1;
                }
                _ => {}
            }

            if wlen == 0 && (part[0] == b'\n' || self.state != ParserState::Init) {
                continue;
            }

            match self.state {
                ParserState::Init => {
                    let word = String::from_utf8(part[0..wlen].to_vec()).unwrap().to_lowercase();

                    if pos == 0 && self.b_count == 0 {
                        if word.starts_with('$') {
                            self.directive_buf = word;
                            self.state = ParserState::Directive;

                        } else {
                            if wlen > 0 {
                                self.name = word;
                            }

                            self.state = ParserState::Common;
                        }
                    }
                }
                ParserState::Common => {
                    let word = String::from_utf8(part[0..wlen].to_vec()).unwrap().to_uppercase();

                    if let Some(class) = RRClasses::from_abbreviation(&word) {
                        self.class = class;

                    } else if let Some(_type) = RRTypes::from_string(&word) {
                        self._type = _type;
                        self.state = ParserState::Data;
                        rec.insert(Record::new(&self.name, self.ttl, self.class, self._type));

                    } else {
                        self.ttl = word.parse().expect(&format!("Parse error on line {} pos {}", self.line_no, pos));
                    }
                }
                ParserState::Directive => {
                    let value = String::from_utf8(part[0..wlen].to_vec()).unwrap().to_uppercase();

                    if self.directive_buf == "$ttl" {
                        self.default_ttl = value.parse().expect(&format!("Parse error on line {} pos {}", self.line_no, pos));

                    } else if self.directive_buf == "$origin" {
                        self.origin = value;

                    } else {
                        panic!("Unknown directive {}", self.directive_buf);
                    }

                    self.state = ParserState::Init;
                }
                ParserState::Data => {
                    if part[0] == b'"' {
                        if part[wlen - 1] == b'"' {
                            rec.as_mut().unwrap().push_data(RecordData::from_bytes(&part[1..wlen - 1]));

                        } else {
                            self.state = ParserState::QString;
                            self.quoted_buf = format!("{}{}", String::from_utf8(part[1..wlen].to_vec()).unwrap(), part[wlen] as char);
                        }

                    } else {
                        rec.as_mut().unwrap().push_data(RecordData::from_bytes(&part[0..wlen]));
                    }
                }
                ParserState::QString => {
                    if part[wlen - 1] == b'"' {
                        //PARSE THIS INTO THE ACTUAL RECORD DATA...

                        let s = format!("{}", String::from_utf8(part[0..wlen - 1].to_vec()).unwrap());
                        self.quoted_buf.push_str(&s);
                        rec.as_mut().unwrap().push_data(RecordData::new(&self.quoted_buf));
                        self.state = ParserState::Data;

                    } else {
                        self.quoted_buf.push_str(&format!("{}{}", String::from_utf8(part[0..wlen].to_vec()).unwrap(), part[wlen] as char));
                    }
                }
            }

            pos += plen;
        }
    }

    pub fn absolute_name(&self, name: &str) -> String {
        assert!(name != "");

        if name == "@" {
            return self.origin.clone();
        }

        if name.ends_with('.') {
            name.to_string()

        } else {
            format!("{}.{}", name, self.origin)
        }
    }
}

impl<'a> Iterator for ZoneParser<'a> {

    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.state = ParserState::Init;
        if self.default_ttl != 0 {
            self.ttl = self.default_ttl;
        }

        let mut rec: Option<Record> = None;

        while !self.end_of_stream {
            self.parse_line(&mut rec);

            if rec.is_some() && self.b_count == 0 {
                return rec;
            }
        }

        None
    }
}
