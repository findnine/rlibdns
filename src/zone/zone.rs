use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read};
use std::ops::DerefMut;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::a_record::ARecord;
use crate::records::aaaa_record::AaaaRecord;
use crate::records::cname_record::CNameRecord;
use crate::records::dnskey_record::DnsKeyRecord;
use crate::records::https_record::HttpsRecord;
use crate::records::inter::record_base::RecordBase;
use crate::records::mx_record::MxRecord;
use crate::records::ns_record::NsRecord;
use crate::records::nsec_record::NSecRecord;
use crate::records::ptr_record::PtrRecord;
use crate::records::rrsig_record::RRSigRecord;
use crate::records::soa_record::SoaRecord;
use crate::records::srv_record::SrvRecord;
use crate::records::txt_record::TxtRecord;
use crate::utils::base64::base64_decode;

#[derive(Debug, PartialEq, Eq)]
enum ParserState {
    Init,
    Common,
    Directive,
    Data,
    QString,
}

pub struct ZoneParser {
    reader: BufReader<File>,
    origin: String,
    name: String,
    default_ttl: u32
}

impl ZoneParser {

    pub fn new(file_path: &str, origin: &str) -> io::Result<Self> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader,
            origin: origin.to_string(),
            name: String::new(),
            default_ttl: 300
        })
    }

    pub fn parse_record(&mut self) -> Option<(String, Box<dyn RecordBase>)> {
        let mut state = ParserState::Init;
        let mut paren_count = 0;

        //let mut name = String::new();
        let mut _type = RRTypes::default();
        let mut class = RRClasses::default();
        let mut ttl = self.default_ttl;

        let mut directive_buf = String::new();

        let mut record: Option<(String, Box<dyn RecordBase>)> = None;
        let mut data_count = 0;
        
        loop {
            let Some(line) = self.reader.by_ref().lines().next() else { break };

            let mut pos = 0;
            let mut quoted_buf = String::new();

            for part in line.ok().unwrap().as_bytes().split_inclusive(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'(' || b == b')') {
                let part_len = part.len();
                let mut word_len = part_len;

                if part[0] == b';' && state != ParserState::QString {
                    break;
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

                match state {
                    ParserState::Init => {
                        let word = String::from_utf8(part[0..word_len].to_vec()).unwrap().to_lowercase();

                        if pos == 0 && paren_count == 0 {
                            if word.starts_with('$') {
                                directive_buf = word;
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

                        } else if let Some(t) = RRTypes::from_string(&word) {
                            _type = t;
                            state = ParserState::Data;
                            data_count = 0;

                            record = Some((self.absolute_name(&self.name), match _type {
                                RRTypes::A => ARecord::new(ttl, class).upcast(),
                                RRTypes::Aaaa => AaaaRecord::new(ttl, class).upcast(),
                                RRTypes::Ns => NsRecord::new(ttl, class).upcast(),
                                RRTypes::Cname => CNameRecord::new(ttl, class).upcast(),
                                RRTypes::Soa => SoaRecord::new(ttl, class).upcast(),
                                RRTypes::Ptr => PtrRecord::new(ttl, class).upcast(),
                                RRTypes::Mx => MxRecord::new(ttl, class).upcast(),
                                RRTypes::Txt => TxtRecord::new(ttl, class).upcast(),
                                RRTypes::Srv => SrvRecord::new(ttl, class).upcast(),
                                //RRTypes::Opt => OptRecord::new(ttl, class).upcast(),
                                RRTypes::Rrsig => RRSigRecord::new(ttl, class).upcast(),
                                RRTypes::Nsec => NSecRecord::new(ttl, class).upcast(),
                                RRTypes::DnsKey => DnsKeyRecord::new(ttl, class).upcast(),
                                RRTypes::Https => HttpsRecord::new(ttl, class).upcast(),
                                //RRTypes::Spf => {}
                                //RRTypes::Tsig => {}
                                //RRTypes::Any => {}
                                //RRTypes::Caa => {}
                                _ => unreachable!()
                            }));

                        } else {
                            ttl = word.parse().unwrap();//.expect(&format!("Parse error on line {} pos {}", self.line_no, pos));
                        }
                    }
                    ParserState::Directive => {
                        let value = String::from_utf8(part[0..word_len].to_vec()).unwrap().to_lowercase();

                        if directive_buf == "$ttl" {
                            self.default_ttl = value.parse().unwrap();//.expect(&format!("Parse error on line {} pos {}", self.line_no, pos));

                        } else if directive_buf == "$origin" {
                            self.origin = match value.strip_suffix('.') {
                                Some(base) => base.to_string(),
                                None => panic!("Domain is not fully qualified (missing trailing dot)")
                            };

                        } else {
                            panic!("Unknown directive {}", directive_buf);
                        }

                        state = ParserState::Init;
                    }
                    ParserState::Data => {
                        if part[0] == b'"' {
                            if part[word_len - 1] == b'"' {
                                if let Some((_, ref mut record)) = record {
                                    set_rdata(record.deref_mut(), data_count, &String::from_utf8(part[1..word_len - 1].to_vec()).unwrap());
                                }

                                data_count += 1;

                            } else {
                                state = ParserState::QString;
                                quoted_buf = format!("{}{}", String::from_utf8(part[1..word_len].to_vec()).unwrap(), part[word_len] as char);
                            }

                        } else {
                            if let Some((_, ref mut record)) = record {
                                set_rdata(record.deref_mut(), data_count, &String::from_utf8(part[0..word_len].to_vec()).unwrap());
                            }

                            data_count += 1;
                        }
                    }
                    ParserState::QString => {
                        if part[word_len - 1] == b'"' {
                            quoted_buf.push_str(&format!("{}", String::from_utf8(part[0..word_len - 1].to_vec()).unwrap()));

                            if let Some((_, ref mut record)) = record {
                                set_rdata(record.deref_mut(), data_count, &quoted_buf);
                            }

                            data_count += 1;
                            state = ParserState::Data;

                        } else {
                            quoted_buf.push_str(&format!("{}{}", String::from_utf8(part[0..word_len].to_vec()).unwrap(), part[word_len] as char));
                        }
                    }
                }

                pos += part_len;
            }

            if record.is_some() && paren_count == 0 {
                return record;
            }
        }

        record
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

    pub fn iter(&mut self) -> ZoneParserIter {
        ZoneParserIter {
            parser: self
        }
    }
}

pub struct ZoneParserIter<'a> {
    parser: &'a mut ZoneParser,
}

impl<'a> Iterator for ZoneParserIter<'a> {

    type Item = (String, Box<dyn RecordBase>);

    fn next(&mut self) -> Option<Self::Item> {
        self.parser.parse_record()
    }
}

/*
impl Iterator for ZoneParser {

    type Item = (String, Box<dyn RecordBase>);

    fn next(&mut self) -> Option<Self::Item> {
        self.parse_record()
    }
}
*/
fn set_rdata(record: &mut dyn RecordBase, pos: usize, value: &str) {
    //WE NEED TO FIX DOMAINS CONTAINING PERIOD...
    match record.get_type() {
        RRTypes::A => record.as_any_mut().downcast_mut::<ARecord>().unwrap().set_address(value.parse().unwrap()),
        RRTypes::Aaaa => record.as_any_mut().downcast_mut::<AaaaRecord>().unwrap().set_address(value.parse().unwrap()),
        RRTypes::Ns => record.as_any_mut().downcast_mut::<NsRecord>().unwrap().set_server(match value.strip_suffix('.') {
            Some(base) => base,
            None => panic!("Domain is not fully qualified (missing trailing dot)")
        }),
        RRTypes::Cname => record.as_any_mut().downcast_mut::<CNameRecord>().unwrap().set_target(match value.strip_suffix('.') {
            Some(base) => base,
            None => panic!("Domain is not fully qualified (missing trailing dot)")
        }),
        RRTypes::Soa => {
            let record = record.as_any_mut().downcast_mut::<SoaRecord>().unwrap();
            match pos {
                0 => record.set_domain(match value.strip_suffix('.') {
                    Some(base) => base,
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                1 => record.set_mailbox(match value.strip_suffix('.') {
                    Some(base) => base,
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                2 => record.set_serial(value.parse().unwrap()),
                3 => record.set_refresh(value.parse().unwrap()),
                4 => record.set_retry(value.parse().unwrap()),
                5 => record.set_expire(value.parse().unwrap()),
                6 => record.set_minimum_ttl(value.parse().unwrap()),
                _ => unimplemented!()
            }
        }
        RRTypes::Ptr => record.as_any_mut().downcast_mut::<PtrRecord>().unwrap().set_domain(match value.strip_suffix('.') {
            Some(base) => base,
            None => panic!("Domain is not fully qualified (missing trailing dot)")
        }),
        RRTypes::Mx => {
            let record = record.as_any_mut().downcast_mut::<MxRecord>().unwrap();
            match pos {
                0 => record.set_priority(value.parse().unwrap()),
                1 => record.set_server(match value.strip_suffix('.') {
                    Some(base) => base,
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                _ => unimplemented!()
            }
        }
        RRTypes::Txt => record.as_any_mut().downcast_mut::<TxtRecord>().unwrap().add_data(value),
        RRTypes::Srv => {
            let record = record.as_any_mut().downcast_mut::<SrvRecord>().unwrap();
            match pos {
                0 => record.set_priority(value.parse().unwrap()),
                1 => record.set_weight(value.parse().unwrap()),
                2 => record.set_port(value.parse().unwrap()),
                3 => record.set_target(match value.strip_suffix('.') {
                    Some(base) => base,
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                _ => unimplemented!()
            }
        }
        RRTypes::Rrsig => {
            let record = record.as_any_mut().downcast_mut::<RRSigRecord>().unwrap();
            match pos {
                0 => record.set_type_covered(value.parse().unwrap()),
                1 => record.set_algorithm(value.parse().unwrap()),
                2 => record.set_labels(value.parse().unwrap()),
                3 => record.set_original_ttl(value.parse().unwrap()),
                4 => record.set_expiration(value.parse().unwrap()),
                5 => record.set_inception(value.parse().unwrap()),
                6 => record.set_key_tag(value.parse().unwrap()),
                7 => record.set_signer_name(match value.strip_suffix('.') {
                    Some(base) => base,
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                8 => record.set_signature(&base64_decode(value).unwrap()),
                _ => unimplemented!()
            }
        }
        RRTypes::Nsec => {}//example.com.  NSEC  next.example.com. A MX RRSIG NSEC
        RRTypes::DnsKey => {}//DNSKEY  <flags> <protocol> <algorithm> <public key>
        RRTypes::Https => {}//HTTPS   <priority> <target> [key=value params...]
        RRTypes::Spf => {}//@       SPF   "v=spf1 include:_spf.example.com ~all"
        RRTypes::Caa => {}//CAA     <flags> <tag> <value>
        _ => unimplemented!()
    }
}
