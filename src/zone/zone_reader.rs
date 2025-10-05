use std::fs::File;
use std::io::{BufRead, BufReader};
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
use crate::utils::coord_utils::encode_loc_precision;
use crate::utils::time_utils::TimeUtils;
use crate::zone::inter::zone_record_data::ZoneRecordData;

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
pub struct ZoneReaderError {
    _type: ErrorKind,
    message: String
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ErrorKind {
    TypeNotFound,
    ParseErr,
    WrongClass,
    FormErr,
    ExtraRRData,
    UnexpectedEof
}

impl ZoneReaderError {

    pub fn new(_type: ErrorKind, message: &str) -> Self {
        Self {
            _type,
            message: message.to_string()
        }
    }
}

impl ZoneReader {

    pub fn open<P: Into<PathBuf>>(file_path: P, origin: &str, class: RRClasses) -> Result<Self, ZoneReaderError> {
        let file = File::open(file_path.into()).map_err(|e| ZoneReaderError::new(ErrorKind::UnexpectedEof, &e.to_string()))?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader,
            origin: origin.to_string(),
            name: String::new(),
            class,
            default_ttl: 300
        })
    }

    pub fn read_record(&mut self, record: &mut Option<(String, u32, Box<dyn ZoneRecordData>)>) -> Result<usize, ZoneReaderError> {
        let mut state = ParserState::Init;
        let mut paren_count: u8 = 0;

        let mut _type;
        let mut ttl = self.default_ttl;

        let mut directive_buf = String::new();

        let mut data_count = 0;

        let mut line = String::new();
        let mut total_length = 0;

        loop {
            line.clear();

            match self.reader.read_line(&mut line) {
                Ok(length) => {
                    if length == 0 {
                        break;
                    }

                    total_length += length;

                    let mut pos = 0;
                    let mut quoted_buf = String::new();

                    for part in line.as_bytes().split_inclusive(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'(' || b == b')') {
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
                                    .map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse string"))?.to_lowercase();

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
                                    .map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse string"))?.to_uppercase();

                                if let Ok(c) = RRClasses::from_str(&word) {
                                    if !c.eq(&self.class) {
                                        return Err(ZoneReaderError::new(ErrorKind::WrongClass, "invalid class found"));
                                    }

                                } else if let Ok(t) = RRTypes::from_str(&word) {
                                    _type = t;
                                    state = ParserState::Data;
                                    data_count = 0;
                                    *record = Some((self.get_relative_name(&self.name).to_string(), ttl, <dyn ZoneRecordData>::new(_type, &self.class)
                                        .ok_or_else(|| ZoneReaderError::new(ErrorKind::TypeNotFound, "record type not found"))?));

                                } else {
                                    ttl = word.parse().map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse number"))?;
                                }
                            }
                            ParserState::Directive => {
                                let value = String::from_utf8(part[0..word_len].to_vec())
                                    .map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse string"))?.to_lowercase();

                                match directive_buf.as_str() {
                                    "$ttl" => self.default_ttl = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse number"))?,
                                    "$origin" => {
                                        self.origin = value.strip_suffix('.').ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "origin is not fully qualified (missing trailing dot)"))?.to_string();
                                    }
                                    _ => return Err(ZoneReaderError::new(ErrorKind::FormErr, &format!("unknown directive {}", directive_buf)))
                                }

                                state = ParserState::Init;
                            }
                            ParserState::Data => {
                                if part[0] == b'"' {
                                    if part[word_len - 1] == b'"' {
                                        record.as_mut().unwrap().2.set_data(data_count, &String::from_utf8(part[1..word_len - 1].to_vec())
                                            .map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse string"))?)?;

                                        data_count += 1;

                                    } else {
                                        state = ParserState::QString;
                                        quoted_buf = format!("{}{}", String::from_utf8(part[1..word_len].to_vec())
                                            .map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse string"))?, part[word_len] as char);
                                    }

                                } else {
                                    record.as_mut().unwrap().2.set_data(data_count, &String::from_utf8(part[0..word_len].to_vec())
                                        .map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse string"))?)?;

                                    data_count += 1;
                                }
                            }
                            ParserState::QString => {
                                if part[word_len - 1] == b'"' {
                                    quoted_buf.push_str(&format!("{}", String::from_utf8(part[0..word_len - 1].to_vec())
                                        .map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse string"))?));

                                    record.as_mut().unwrap().2.set_data(data_count, &quoted_buf)?;

                                    data_count += 1;
                                    state = ParserState::Data;

                                } else {
                                    quoted_buf.push_str(&format!("{}{}", String::from_utf8(part[0..word_len].to_vec())
                                        .map_err(|_| ZoneReaderError::new(ErrorKind::ParseErr, "unable to parse string"))?, part[word_len] as char));
                                }
                            }
                        }

                        pos += part_len;
                    }

                    if record.is_some() && paren_count == 0 {
                        return Ok(total_length);
                    }
                }
                Err(e) => return Err(ZoneReaderError::new(ErrorKind::UnexpectedEof, &e.to_string()))
            }
        }

        Ok(total_length)
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

    pub fn records(&mut self) -> ZoneReaderIter {
        ZoneReaderIter {
            reader: self
        }
    }
}

pub struct ZoneReaderIter<'a> {
    reader: &'a mut ZoneReader
}

impl<'a> Iterator for ZoneReaderIter<'a> {

    type Item = Result<(String, u32, Box<dyn ZoneRecordData>), ZoneReaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut record = None;

        match self.reader.read_record(&mut record) {
            Ok(length) => {
                if length == 0 {
                    return None;
                }

                match record {
                    Some(record) => Some(Ok(record)),
                    None => self.next()
                }
            }
            Err(e) => Some(Err(e))
        }
    }
}

fn set_data1(class: &RRClasses, record: &mut dyn ZoneRecordData, pos: usize, value: &str) -> Result<(), ZoneReaderError> {
    /*
    match record.get_type() {
        RRTypes::A => {
            match class {
                RRClasses::Ch => {
                    let record = record.as_any_mut().downcast_mut::<ChARecord>().unwrap();

                    match pos {
                        0 => record.network = Some(value.strip_suffix('.')
                            .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "network param is not fully qualified (missing trailing dot)"))?.to_string()),
                        1 => record.address = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse address param"))?,
                        _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
                    }
                }
                _ => record.as_any_mut().downcast_mut::<InARecord>().unwrap().address = Some(value.parse()
                    .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse address param"))?)
            }
        }
        RRTypes::Aaaa => record.as_any_mut().downcast_mut::<AaaaRecord>().unwrap().address = Some(value.parse()
            .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse address param"))?,),
        RRTypes::Ns => record.as_any_mut().downcast_mut::<NsRecord>().unwrap().server = Some(value.strip_suffix('.')
            .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "server param is not fully qualified (missing trailing dot)"))?.to_string()),
        RRTypes::CName => record.as_any_mut().downcast_mut::<CNameRecord>().unwrap().target = Some(value.strip_suffix('.')
            .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "target param is not fully qualified (missing trailing dot)"))?.to_string()),
        RRTypes::Soa => {
            let record = record.as_any_mut().downcast_mut::<SoaRecord>().unwrap();
            match pos {
                0 => record.fqdn = Some(value.strip_suffix('.')
                    .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "fqdn param is not fully qualified (missing trailing dot)"))?.to_string()),
                1 => record.mailbox = Some(value.strip_suffix('.')
                    .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "mailbox param is not fully qualified (missing trailing dot)"))?.to_string()),
                2 => record.serial = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse serial param"))?,
                3 => record.refresh = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse refresh param"))?,
                4 => record.retry = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse retry param"))?,
                5 => record.expire = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse expire param"))?,
                6 => record.minimum_ttl = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse minimum_ttl param"))?,
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::Ptr => record.as_any_mut().downcast_mut::<PtrRecord>().unwrap().fqdn = Some(value.strip_suffix('.')
            .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "fqdn param is not fully qualified (missing trailing dot)"))?.to_string()),





        RRTypes::HInfo => {
            let record = record.as_any_mut().downcast_mut::<HInfoRecord>().unwrap();
            match pos {
                0 => record.cpu = Some(value.to_string()),
                1 => record.os = Some(value.to_string()),
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::Mx => {
            let record = record.as_any_mut().downcast_mut::<MxRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse priority param"))?,
                1 => record.server = Some(value.strip_suffix('.')
                    .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "server param is not fully qualified (missing trailing dot)"))?.to_string()),
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::Txt => record.as_any_mut().downcast_mut::<TxtRecord>().unwrap().data.push(value.to_string()),
        RRTypes::Loc => {
            let record = record.as_any_mut().downcast_mut::<LocRecord>().unwrap();
            match pos {
                0 => record.latitude = value.parse::<u32>()
                    .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse latitude 1 param"))? * 3_600_000,
                1 => record.latitude = record.latitude + value.parse::<u32>()
                    .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse latitude 2 param"))? * 60_000,
                2 => record.latitude += (value.parse::<f64>()
                    .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse latitude 3 param"))? * 1000.0).round() as u32,
                3 => {
                    let sign = match value {
                        "S" | "W" => -1,
                        "N" | "E" => 1,
                        _ => return Err(ZoneReaderError::new(ErrorKind::FormErr, "invalid direction"))
                    };

                    let val = (sign * (record.latitude as i64)) + (1 << 31);
                    record.latitude = val as u32
                }
                4 => record.longitude = value.parse::<u32>()
                    .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse longitude 1 param"))? * 3_600_000,
                5 => record.longitude = record.longitude + value.parse::<u32>()
                    .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse longitude 2 param"))? * 60_000,
                6 => record.longitude += (value.parse::<f64>()
                    .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse longitude 3 param"))? * 1000.0).round() as u32,
                7 => {
                    let sign = match value {
                        "S" | "W" => -1,
                        "N" | "E" => 1,
                        _ => return Err(ZoneReaderError::new(ErrorKind::FormErr, "invalid direction"))
                    };

                    let val = (sign * (record.longitude as i64)) + (1 << 31);
                    record.longitude = val as u32
                }
                8 => {
                    let clean = value.trim_end_matches('m');
                    record.altitude = (clean.parse::<f64>()
                        .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse altitude param"))? * 100.0).round() as u32;
                }
                9 => record.size = encode_loc_precision(value).map_err(|e| ZoneReaderError::new(ErrorKind::FormErr, &e.to_string()))?,
                10 => record.h_precision = encode_loc_precision(value).map_err(|e| ZoneReaderError::new(ErrorKind::FormErr, &e.to_string()))?,
                11 => record.v_precision = encode_loc_precision(value).map_err(|e| ZoneReaderError::new(ErrorKind::FormErr, &e.to_string()))?,
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::Srv => {
            let record = record.as_any_mut().downcast_mut::<SrvRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse priority param"))?,
                1 => record.weight = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to weight port param"))?,
                2 => record.port = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse port param"))?,
                3 => record.target = Some(value.strip_suffix('.')
                    .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "target param is not fully qualified (missing trailing dot)"))?.to_string()),
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::Naptr => {
            let record = record.as_any_mut().downcast_mut::<NaptrRecord>().unwrap();
            match pos {
                0 => record.order = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse order param"))?,
                1 => record.preference = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse preference param"))?,
                2 => {
                    let mut flags = Vec::new();

                    for flag in value.split(",") {
                        let tok = flag.trim();
                        if tok.is_empty() {
                            continue;
                        }

                        flags.push(NaptrFlags::try_from(flag.chars()
                            .next()
                            .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "empty NAPTR flag token"))?)
                            .map_err(|e|ZoneReaderError::new(ErrorKind::FormErr, &e.to_string()))?);
                    }

                    record.flags = flags;
                }
                3 => record.service = Some(value.to_string()),
                4 => record.regex = Some(value.to_string()),
                5 => record.replacement = Some(value.strip_suffix('.')
                    .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "replacement param is not fully qualified (missing trailing dot)"))?.to_string()),
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::SshFp => {
            let record = record.as_any_mut().downcast_mut::<SshFpRecord>().unwrap();
            match pos {
                0 => record.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse algorithm param"))?,
                1 => record.fingerprint_type = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse fingerprint_type param"))?,
                2 => record.fingerprint = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse fingerprint param"))?,
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::RRSig => {
            let record = record.as_any_mut().downcast_mut::<RRSigRecord>().unwrap();
            match pos {
                0 => record.type_covered = RRTypes::from_str(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse type_covered param"))?,
                1 => record.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse algorithm param"))?,
                2 => record.labels = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse labels param"))?,
                3 => record.original_ttl = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse original_ttl param"))?,
                4 => record.expiration = u32::from_time_format(value),
                5 => record.inception = u32::from_time_format(value),
                6 => record.key_tag = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse key_tag param"))?,
                7 => record.signer_name = Some(value.strip_suffix('.')
                    .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "signer_name param is not fully qualified (missing trailing dot)"))?.to_string()),
                8 => record.signature = base64::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse signature param"))?,
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::Nsec => {}//example.com.  NSEC  next.example.com. A MX RRSIG NSEC
        RRTypes::DnsKey => {}//DNSKEY  <flags> <protocol> <algorithm> <public key>
        RRTypes::Smimea => {
            let record = record.as_any_mut().downcast_mut::<SmimeaRecord>().unwrap();
            match pos {
                0 => record.usage = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse usage param"))?,
                1 => record.selector = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse selector param"))?,
                2 => record.matching_type = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse matching_type param"))?,
                3 => record.certificate = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse ceritificate param"))?,
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::Svcb => {
            let record = record.as_any_mut().downcast_mut::<SvcbRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse priority param"))?,
                1 => record.target = Some(value.strip_suffix('.')
                    .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "target param is not fully qualified (missing trailing dot)"))?.to_string()),
                _ => record.params.push(SvcParams::from_str(value).map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse params param"))?)
            }
        }
        RRTypes::Https => {
            let record = record.as_any_mut().downcast_mut::<HttpsRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse priority param"))?,
                1 => record.target = Some(value.strip_suffix('.')
                    .ok_or_else(|| ZoneReaderError::new(ErrorKind::FormErr, "target param is not fully qualified (missing trailing dot)"))?.to_string()),
                _ => record.params.push(SvcParams::from_str(value).unwrap())
            }
        }
        RRTypes::Spf => {}//@       SPF   "v=spf1 include:_spf.example.com ~all"
        RRTypes::Uri => {
            let record = record.as_any_mut().downcast_mut::<UriRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse priority param"))?,
                1 => record.weight = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse weight param"))?,
                2 => record.target = Some(value.to_string()),
                _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found"))
            }
        }
        RRTypes::Caa => {}//CAA     <flags> <tag> <value>
        _ => unimplemented!()
    }
    */

    Ok(())
}
