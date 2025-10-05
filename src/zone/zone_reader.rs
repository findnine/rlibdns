use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read};
use std::ops::DerefMut;
use std::path::PathBuf;
use std::str::FromStr;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::{
    in_a_record::InARecord,
    ch_a_record::ChARecord,
    aaaa_record::AaaaRecord,
    cname_record::CNameRecord,
    dnskey_record::DnsKeyRecord,
    hinfo_record::HInfoRecord,
    https_record::HttpsRecord,
    loc_record::LocRecord,
    mx_record::MxRecord,
    naptr_record::NaptrRecord,
    ns_record::NsRecord,
    nsec_record::NSecRecord,
    ptr_record::PtrRecord,
    rrsig_record::RRSigRecord,
    smimea_record::SmimeaRecord,
    soa_record::SoaRecord,
    srv_record::SrvRecord,
    sshfp_record::SshFpRecord,
    svcb_record::SvcbRecord,
    txt_record::TxtRecord,
    uri_record::UriRecord,
};
use crate::records::inter::naptr_flags::NaptrFlags;
use crate::records::inter::record_base::RecordBase;
use crate::records::inter::svc_param::SvcParams;
use crate::utils::{base64, hex};
use crate::utils::time_utils::TimeUtils;

#[derive(Debug, PartialEq, Eq)]
enum ParserState {
    Init,
    Common,
    Directive,
    Data,
    QString
}

pub struct ZoneReader {
    reader: BufReader<File>,
    origin: String,
    name: String,
    class: RRClasses,
    default_ttl: u32
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ZoneReaderParseError {
    NotFound(String),
    ParseErr(String),
    FormErr(String),
    ExtraRRData(String),
    UnknownParse(String)
}

impl ZoneReader {

    pub fn open<P: Into<PathBuf>>(file_path: P, origin: &str, class: RRClasses) -> io::Result<Self> {
        let file = File::open(file_path.into())?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader,
            origin: origin.to_string(),
            name: String::new(),
            class,
            default_ttl: 300
        })
    }

    fn parse_record(&mut self) -> Result<Option<(String, u32, Box<dyn RecordBase>)>, ZoneReaderParseError> {
        let mut state = ParserState::Init;
        let mut paren_count = 0;

        let mut _type = RRTypes::default();
        let mut ttl = self.default_ttl;

        let mut directive_buf = String::new();

        let mut record: Option<(String, u32, Box<dyn RecordBase>)> = None;
        let mut data_count = 0;

        loop {
            let Some(line) = self.reader.by_ref().lines().next() else { break };

            let mut pos = 0;
            let mut quoted_buf = String::new();

            for part in line.map_err(|e| ZoneReaderParseError::FormErr("end of file".to_string()))?
                    .as_bytes().split_inclusive(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'(' || b == b')') {
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
                        let word = String::from_utf8(part[0..word_len].to_vec())
                            .map_err(|e| ZoneReaderParseError::ParseErr(e.to_string()))?.to_lowercase();

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
                        let word = String::from_utf8(part[0..word_len].to_vec())
                            .map_err(|e| ZoneReaderParseError::ParseErr(e.to_string()))?.to_uppercase();

                        if let Ok(t) = RRTypes::from_str(&word) {
                            _type = t;
                            state = ParserState::Data;
                            data_count = 0;
                            record = Some((self.get_relative_name(&self.name).to_string(), ttl, <dyn RecordBase>::new(_type, self.class)
                                .ok_or_else(|| ZoneReaderParseError::NotFound("record type is unknown".to_string()))?));

                        } else if RRClasses::from_str(&word).is_err() {
                            ttl = word.parse()
                                .map_err(|_| ZoneReaderParseError::ParseErr("ttl was unparsable".to_string()))?;
                        }
                    }
                    ParserState::Directive => {
                        let value = String::from_utf8(part[0..word_len].to_vec())
                            .map_err(|e| ZoneReaderParseError::ParseErr(e.to_string()))?.to_lowercase();

                        match directive_buf.as_str() {
                            "$ttl" => self.default_ttl = value.parse().map_err(|_| ZoneReaderParseError::ParseErr("default ttl was unparsable".to_string()))?,
                            "$origin" => {
                                self.origin = match value.strip_suffix('.') {
                                    Some(base) => base.to_string(),
                                    None => return Err(ZoneReaderParseError::FormErr("origin is not fully qualified (missing trailing dot)".to_string()))
                                };
                            }
                            _ => return Err(ZoneReaderParseError::FormErr(format!("unknown directive {}", directive_buf)))
                        }

                        state = ParserState::Init;
                    }
                    ParserState::Data => {
                        if part[0] == b'"' {
                            if part[word_len - 1] == b'"' {
                                if let Some((_, _, ref mut record)) = record {
                                    set_data(&self.class, record.deref_mut(), data_count, &String::from_utf8(part[1..word_len - 1].to_vec())
                                        .map_err(|e| ZoneReaderParseError::ParseErr(e.to_string()))?)?;
                                }

                                data_count += 1;

                            } else {
                                state = ParserState::QString;
                                quoted_buf = format!("{}{}", String::from_utf8(part[1..word_len].to_vec())
                                    .map_err(|e| ZoneReaderParseError::ParseErr(e.to_string()))?, part[word_len] as char);
                            }

                        } else {
                            if let Some((_, _, ref mut record)) = record {
                                set_data(&self.class, record.deref_mut(), data_count, &String::from_utf8(part[0..word_len].to_vec())
                                    .map_err(|e| ZoneReaderParseError::ParseErr(e.to_string()))?)?;
                            }

                            data_count += 1;
                        }
                    }
                    ParserState::QString => {
                        if part[word_len - 1] == b'"' {
                            quoted_buf.push_str(&format!("{}", String::from_utf8(part[0..word_len - 1].to_vec())
                                .map_err(|e| ZoneReaderParseError::ParseErr(e.to_string()))?));

                            if let Some((_, _, ref mut record)) = record {
                                set_data(&self.class, record.deref_mut(), data_count, &quoted_buf)?;
                            }

                            data_count += 1;
                            state = ParserState::Data;

                        } else {
                            quoted_buf.push_str(&format!("{}{}", String::from_utf8(part[0..word_len].to_vec())
                                .map_err(|e| ZoneReaderParseError::ParseErr(e.to_string()))?, part[word_len] as char));
                        }
                    }
                }

                pos += part_len;
            }

            if record.is_some() && paren_count == 0 {
                return Ok(record);
            }
        }

        Ok(record)
    }

    pub fn get_origin(&self) -> &str {
        &self.origin
    }

    pub fn get_relative_name<'a>(&self, name: &'a str) -> &'a str {
        if name.eq("@") {
            return "";
        }

        &name
    }
    /*
    pub fn absolute_name(&self, name: &str) -> String {
        assert!(name != "");

        if name == "@" {
            return name.to_string();//self.origin.clone();
        }

        if name.ends_with('.') {
            name.to_string()

        } else {
            format!("{}.{}", name, self.origin)
        }
    }
    */

    pub fn iter(&mut self) -> ZoneReaderIter {
        ZoneReaderIter {
            parser: self
        }
    }
}

pub struct ZoneReaderIter<'a> {
    parser: &'a mut ZoneReader
}

impl<'a> Iterator for ZoneReaderIter<'a> {

    type Item = Result<Option<(String, u32, Box<dyn RecordBase>)>, ZoneReaderParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.parser.parse_record()
    }
}

fn set_data(class: &RRClasses, record: &mut dyn RecordBase, pos: usize, value: &str) -> Result<(), ZoneReaderParseError> {
    match record.get_type() {
        RRTypes::A => {
            match class {
                RRClasses::Ch => {
                    let record = record.as_any_mut().downcast_mut::<ChARecord>()
                        .ok_or(ZoneReaderParseError::ExtraRRData(value.to_string()))?;

                    match pos {
                        0 => record.network = Some(match value.strip_suffix('.') {
                            Some(base) => base.to_string(),
                            None => panic!("network param is not fully qualified (missing trailing dot)")
                        }),
                        1 => record.address = value.parse().unwrap(),
                        _ => unimplemented!()
                    }
                }
                _ => record.as_any_mut().downcast_mut::<InARecord>().unwrap().address = Some(value.parse().unwrap())
            }
        }
        RRTypes::Aaaa => record.as_any_mut().downcast_mut::<AaaaRecord>().unwrap().address = Some(value.parse().unwrap()),
        RRTypes::Ns => record.as_any_mut().downcast_mut::<NsRecord>().unwrap().server = Some(match value.strip_suffix('.') {
            Some(base) => base.to_string(),
            None => panic!("server param is not fully qualified (missing trailing dot)")
        }),
        RRTypes::CName => record.as_any_mut().downcast_mut::<CNameRecord>().unwrap().target = Some(match value.strip_suffix('.') {
            Some(base) => base.to_string(),
            None => panic!("target param is not fully qualified (missing trailing dot)")
        }),
        RRTypes::Soa => {
            let record = record.as_any_mut().downcast_mut::<SoaRecord>().unwrap();
            match pos {
                0 => record.fqdn = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("fqdn param is not fully qualified (missing trailing dot)")
                }),
                1 => record.mailbox = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("mailbox param is not fully qualified (missing trailing dot)")
                }),
                2 => record.serial = value.parse().unwrap(),
                3 => record.refresh = value.parse().unwrap(),
                4 => record.retry = value.parse().unwrap(),
                5 => record.expire = value.parse().unwrap(),
                6 => record.minimum_ttl = value.parse().unwrap(),
                _ => unimplemented!()
            }
        }
        RRTypes::Ptr => record.as_any_mut().downcast_mut::<PtrRecord>().unwrap().fqdn = Some(match value.strip_suffix('.') {
            Some(base) => base.to_string(),
            None => panic!("fqdn param is not fully qualified (missing trailing dot)")
        }),
        RRTypes::HInfo => {
            let record = record.as_any_mut().downcast_mut::<HInfoRecord>().unwrap();
            match pos {
                0 => record.cpu = Some(value.to_string()),
                1 => record.os = Some(value.to_string()),
                _ => unimplemented!()
            }
        }
        RRTypes::Mx => {
            let record = record.as_any_mut().downcast_mut::<MxRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.server = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("server param is not fully qualified (missing trailing dot)")
                }),
                _ => unimplemented!()
            }
        }
        RRTypes::Txt => record.as_any_mut().downcast_mut::<TxtRecord>().unwrap().data.push(value.to_string()),
        RRTypes::Loc => {
            let record = record.as_any_mut().downcast_mut::<LocRecord>().unwrap();
            match pos {
                0 => record.latitude = value.parse::<u32>().unwrap() * 3_600_000,
                1 => record.latitude = record.latitude + value.parse::<u32>().unwrap() * 60_000,
                2 => record.latitude += (value.parse::<f64>().unwrap() * 1000.0).round() as u32,
                3 => {
                    let sign = match value {
                        "S" | "W" => -1,
                        "N" | "E" => 1,
                        _ => panic!("invalid direction")
                    };

                    let val = (sign * (record.latitude as i64)) + (1 << 31);
                    record.latitude = val as u32
                }
                4 => record.longitude = value.parse::<u32>().unwrap() * 3_600_000,
                5 => record.longitude = record.longitude + value.parse::<u32>().unwrap() * 60_000,
                6 => record.longitude += (value.parse::<f64>().unwrap() * 1000.0).round() as u32,
                7 => {
                    let sign = match value {
                        "S" | "W" => -1,
                        "N" | "E" => 1,
                        _ => panic!("invalid direction")
                    };

                    let val = (sign * (record.longitude as i64)) + (1 << 31);
                    record.longitude = val as u32
                }
                8 => {
                    let clean = value.trim_end_matches('m');
                    record.altitude = (clean.parse::<f64>().unwrap() * 100.0).round() as u32;
                }
                9 => {
                    record.size = encode_loc_precision(value);
                }
                10 => {
                    record.h_precision = encode_loc_precision(value);
                }
                11 => {
                    record.v_precision = encode_loc_precision(value);
                }
                _ => unimplemented!()
            }
        }
        RRTypes::Srv => {
            let record = record.as_any_mut().downcast_mut::<SrvRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.weight = value.parse().unwrap(),
                2 => record.port = value.parse().unwrap() ,
                3 => record.target = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("target param is not fully qualified (missing trailing dot)")
                }),
                _ => unimplemented!()
            }
        }
        RRTypes::Naptr => {
            let record = record.as_any_mut().downcast_mut::<NaptrRecord>().unwrap();
            match pos {
                0 => record.order = value.parse().unwrap(),
                1 => record.preference = value.parse().unwrap(),
                2 => record.flags = value.split(",")
                    .filter_map(|tok| {
                        let tok = tok.trim();
                        if tok.is_empty() {
                            return None;
                        }
                        tok.chars().next().map(|c| NaptrFlags::try_from(c).unwrap())
                    }).collect::<Vec<_>>(),
                3 => record.service = Some(value.to_string()),
                4 => record.regex = Some(value.to_string()),
                5 => record.replacement = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("replacement param is not fully qualified (missing trailing dot)")
                }),
                _ => unimplemented!()
            }
        }
        RRTypes::SshFp => {
            let record = record.as_any_mut().downcast_mut::<SshFpRecord>().unwrap();
            match pos {
                0 => record.algorithm = value.parse().unwrap(),
                1 => record.fingerprint_type = value.parse().unwrap(),
                2 => record.fingerprint = hex::decode(value).unwrap(),
                _ => unimplemented!()
            }
        }
        RRTypes::RRSig => {
            let record = record.as_any_mut().downcast_mut::<RRSigRecord>().unwrap();
            match pos {
                0 => record.type_covered = RRTypes::from_str(value).unwrap(),
                1 => record.algorithm = value.parse().unwrap(),
                2 => record.labels = value.parse().unwrap(),
                3 => record.original_ttl = value.parse().unwrap(),
                4 => record.expiration = u32::from_time_format(value),
                5 => record.inception = u32::from_time_format(value),
                6 => record.key_tag = value.parse().unwrap(),
                7 => record.signer_name = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("signer_name param is not fully qualified (missing trailing dot)")
                }),
                8 => record.signature = base64::decode(value).unwrap(),
                _ => record.signature.extend_from_slice(&base64::decode(value).unwrap())
            }
        }
        RRTypes::Nsec => {}//example.com.  NSEC  next.example.com. A MX RRSIG NSEC
        RRTypes::DnsKey => {}//DNSKEY  <flags> <protocol> <algorithm> <public key>
        RRTypes::Smimea => {
            let record = record.as_any_mut().downcast_mut::<SmimeaRecord>().unwrap();
            match pos {
                0 => record.usage = value.parse().unwrap(),
                1 => record.selector = value.parse().unwrap(),
                2 => record.matching_type = value.parse().unwrap(),
                3 => record.certificate = hex::decode(value).unwrap(),
                _ => unimplemented!()
            }
        }
        RRTypes::Svcb => {
            let record = record.as_any_mut().downcast_mut::<SvcbRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.target = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("target param is not fully qualified (missing trailing dot)")
                }),
                _ => record.params.push(SvcParams::from_str(value).unwrap())
            }
        }
        RRTypes::Https => {
            let record = record.as_any_mut().downcast_mut::<HttpsRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.target = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("target param is not fully qualified (missing trailing dot)")
                }),
                _ => record.params.push(SvcParams::from_str(value).unwrap())
            }
        }
        RRTypes::Spf => {}//@       SPF   "v=spf1 include:_spf.example.com ~all"
        RRTypes::Uri => {
            let record = record.as_any_mut().downcast_mut::<UriRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.weight = value.parse().unwrap(),
                2 => record.target = Some(value.to_string()),
                _ => unimplemented!()
            }
        }
        RRTypes::Caa => {}//CAA     <flags> <tag> <value>
        _ => unimplemented!()
    }

    Ok(())
}

fn encode_loc_precision(s: &str) -> u8 {
    let val = s.strip_suffix('m').unwrap_or(s).parse::<f64>().unwrap();
    for exp in 0..=9 {
        for base in 0..=9 {
            let encoded = (base as f64) * 10f64.powi(exp);
            if (val - encoded).abs() < 0.5 {
                return ((base << 4) | exp).try_into().unwrap();
            }
        }
    }
    panic!("cannot encode LOC precision from value: {}", s);
}
