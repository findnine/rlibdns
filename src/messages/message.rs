use std::array::from_fn;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::SocketAddr;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::messages::inter::rr_classes::RRClasses;
use crate::records::inter::record_base::RecordBase;
use crate::messages::rr_query::RRQuery;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::rr_name::RRName;
use crate::messages::rr_set::RRSet;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
/*
                               1  1  1  1  1  1
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

pub const DNS_HEADER_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct Message {
    id: u16,
    op_code: OpCodes,
    response_code: ResponseCodes,
    qr: bool,
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authenticated_data: bool,
    checking_disabled: bool,
    origin: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    queries: Vec<RRQuery>,
    sections: [Vec<RRName>; 3],
    option: Option<OpCodes>
}

impl Default for Message {

    fn default() -> Self {
        Self {
            id: 0,
            op_code: OpCodes::Query,
            response_code: ResponseCodes::NoError,
            qr: false,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authenticated_data: false,
            checking_disabled: false,
            origin: None,
            destination: None,
            queries: Vec::new(),
            sections: Default::default(),
            option: None
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MessageError {
    HeaderError(String),
    RecordError(String)
}

impl Message {

    pub fn new(id: u16) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, MessageError> {
        let id = u16::from_be_bytes([buf[0], buf[1]]);

        let flags = u16::from_be_bytes([buf[2], buf[3]]);

        let qr = (flags & 0x8000) != 0;
        let op_code = OpCodes::try_from(((flags >> 11) & 0x0F) as u8).map_err(|e| MessageError::HeaderError(e.to_string()))?;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        //let z = (flags & 0x0040) != 0;
        let authenticated_data = (flags & 0x0020) != 0;
        let checking_disabled = (flags & 0x0010) != 0;
        let response_code = ResponseCodes::try_from((flags & 0x000F) as u8).map_err(|e| MessageError::HeaderError(e.to_string()))?;

        let qd_count = u16::from_be_bytes([buf[4], buf[5]]);

        let mut queries = Vec::new();
        let mut off = DNS_HEADER_LEN;

        for _ in 0..qd_count {
            queries.push(RRQuery::from_bytes(buf, &mut off));
        }

        let sections = [
            records_from_bytes(buf, &mut off, u16::from_be_bytes([buf[6], buf[7]]))?,
            records_from_bytes(buf, &mut off, u16::from_be_bytes([buf[8], buf[9]]))?,
            records_from_bytes(buf, &mut off, u16::from_be_bytes([buf[10], buf[11]]))?
        ];

        Ok(Self {
            id,
            op_code,
            response_code,
            qr,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authenticated_data,
            checking_disabled,
            origin: None,
            destination: None,
            queries,
            sections,
            option: None
        })
    }

    //TRUNCATE WILL BE HANDLED BY ITERATOR...
    pub fn to_bytes(&self, max_payload_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; DNS_HEADER_LEN];

        buf.splice(0..2, self.id.to_be_bytes());

        buf.splice(4..6, (self.queries.len() as u16).to_be_bytes());

        let mut compression_data = HashMap::new();
        let mut off = DNS_HEADER_LEN;
        let mut truncated = false;

        for query in &self.queries {
            let q = query.to_bytes(&mut compression_data, off);
            if off+q.len() > max_payload_len {
                truncated = true;
                break;
            }

            buf.extend_from_slice(&q);
            off += q.len();
        }

        if !truncated {
            for (i, section) in self.sections.iter().enumerate() {
                let (records, count, t) = records_to_bytes(off, section, &mut compression_data, max_payload_len);
                buf.extend_from_slice(&records);
                buf.splice(i*2+6..i*2+8, count.to_be_bytes());

                if t {
                    truncated = t;
                    break;
                }
            }
        }

        let flags = (if self.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.op_code as u16 & 0x0F) << 11) |  // Opcode
            (if self.authoritative { 0x0400 } else { 0 }) |  // AA bit
            (if truncated { 0x0200 } else { 0 }) |  // TC bit
            (if self.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.response_code as u16 & 0x000F);  // RCODE

        buf.splice(2..4, flags.to_be_bytes());

        buf
    }

    pub fn wire_chunks(&self, max_payload_len: usize) -> WireIter {
        WireIter {
            message: self,
            position: 0,
            total: from_fn(|i| self.total_section(i)),
            max_payload_len
        }
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn set_qr(&mut self, qr: bool) {
        self.qr = qr;
    }

    pub fn is_qr(&self) -> bool {
        self.qr
    }

    pub fn set_op_code(&mut self, op_code: OpCodes) {
        self.op_code = op_code;
    }

    pub fn get_op_code(&self) -> OpCodes {
        self.op_code.clone()
    }

    pub fn set_origin(&mut self, origin: SocketAddr) {
        self.origin = Some(origin);
    }

    pub fn get_origin(&self) -> Option<SocketAddr> {
        self.origin
    }

    pub fn set_destination(&mut self, destination: SocketAddr) {
        self.destination = Some(destination);
    }

    pub fn get_destination(&self) -> Option<SocketAddr> {
        self.destination
    }

    pub fn set_authoritative(&mut self, authoritative: bool) {
        self.authoritative = authoritative;
    }

    pub fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    pub fn set_truncated(&mut self, truncated: bool) {
        self.truncated = truncated;
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn set_recursion_desired(&mut self, recursion_desired: bool) {
        self.recursion_desired = recursion_desired;
    }

    pub fn is_recursion_desired(&self) -> bool {
        self.recursion_desired
    }

    pub fn set_recursion_available(&mut self, recursion_available: bool) {
        self.recursion_available = recursion_available;
    }

    pub fn is_recursion_available(&self) -> bool {
        self.recursion_available
    }

    pub fn set_response_code(&mut self, response_code: ResponseCodes) {
        self.response_code = response_code;
    }

    pub fn get_response_code(&self) -> ResponseCodes {
        self.response_code
    }

    pub fn has_queries(&self) -> bool {
        !self.queries.is_empty()
    }

    pub fn add_query(&mut self, query: RRQuery) {
        self.queries.push(query);
    }

    pub fn get_queries(&self) -> &Vec<RRQuery> {
        self.queries.as_ref()
    }

    pub fn get_queries_mut(&mut self) -> &mut Vec<RRQuery> {
        self.queries.as_mut()
    }

    pub fn has_section(&self, index: usize) -> bool {
        !self.sections[index].is_empty()
    }

    pub fn set_section(&mut self, index: usize, section: Vec<RRName>) {
        self.sections[index] = section;
    }

    pub fn add_section(&mut self, index: usize, query: &RRQuery, ttl: u32, record: Box<dyn RecordBase>) {
        let fqdn = query.get_fqdn();

        let name = match self.sections[index].iter_mut().find(|name| fqdn.eq(name.get_fqdn())) {
            Some(n) => n,
            None => {
                self.sections[index].push(RRName::new(&fqdn));
                self.sections[index].last_mut().unwrap()
            }
        };

        let _type = query.get_type();
        let class = query.get_class();

        if let Some(set) = name
            .get_sets_mut()
            .iter_mut()
            .find(|s| s.get_type().eq(&_type) && s.get_class().eq(&class))
        {
            set.add_record(ttl, record);
        } else {
            let mut set = RRSet::new(_type, class, ttl);
            set.add_record(ttl, record);
            name.add_set(set);
        }
    }

    pub fn get_section(&self, index: usize) -> &Vec<RRName> {
        self.sections[index].as_ref()
    }

    pub fn get_section_mut(&mut self, index: usize) -> &mut Vec<RRName> {
        self.sections[index].as_mut()
    }

    pub fn total_section(&self, index: usize) -> usize {
        self.sections[index].iter().map(|n| n.get_sets().iter().map(|s| s.total_records()).sum::<usize>()).sum()
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl fmt::Display for Message {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, ";; ->>HEADER<<- opcode: {}, status: {}, id: {}", self.op_code, self.response_code, self.id)?;

        let mut flags = Vec::new();

        if self.qr { flags.push("qr"); }
        if self.authoritative { flags.push("aa"); }
        if self.truncated { flags.push("tc"); }
        if self.recursion_desired { flags.push("rd"); }
        if self.recursion_available { flags.push("ra"); }
        if self.authenticated_data { flags.push("ad"); }
        if self.checking_disabled { flags.push("cd"); }

        writeln!(f, ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
                flags.join(" "),
                self.queries.len(),
                self.sections[0].len(),
                self.sections[1].len(),
                self.sections[2].len())?;

        /*
        if let Some(r) = self.additional_records.get(&String::new()) {
            for r in r {
                if r.get_type().eq(&RRTypes::Opt) {
                    writeln!(f, "\r\n;; OPT PSEUDOSECTION:")?;
                    writeln!(f, "{}", self.additional_records.get(&String::new()).unwrap().get(0).unwrap())?;
                }
            }
        }
        */



        writeln!(f, "\r\n;; QUESTION SECTION:")?;
        for q in &self.queries {
            writeln!(f, ";{}", q)?;
        }

        if !self.sections[0].is_empty() {
            writeln!(f, "\r\n;; ANSWER SECTION:")?;

            for name in self.sections[0].iter() {
                let fqdn = format!("{}.", name.get_fqdn());
                for set in name.get_sets() {
                    for record in set.get_records() {
                        writeln!(f, "{:<24}{:<8}{:<8}{}", fqdn, set.get_ttl(), set.get_class().to_string(), record)?;
                    }
                }
            }
        }

        if !self.sections[1].is_empty() {
            writeln!(f, "\r\n;; AUTHORITATIVE SECTION:")?;

            for name in self.sections[1].iter() {
                let fqdn = format!("{}.", name.get_fqdn());
                for set in name.get_sets() {
                    for record in set.get_records() {
                        writeln!(f, "{:<24}{:<8}{:<8}{}", fqdn, set.get_ttl(), set.get_class().to_string(), record)?;
                    }
                }
            }
        }

        if !self.sections[2].is_empty() {
            writeln!(f, "\r\n;; ADDITIONAL SECTION:")?;

            for name in self.sections[2].iter() {
                let fqdn = format!("{}.", name.get_fqdn());
                for set in name.get_sets() {
                    for record in set.get_records() {
                        writeln!(f, "{:<24}{:<8}{:<8}{}", fqdn, set.get_ttl(), set.get_class().to_string(), record)?;
                    }
                }
            }
        }

        Ok(())
    }
}

pub struct WireIter<'a> {
    message: &'a Message,
    position: usize,
    total: [usize; 3],
    max_payload_len: usize
}

impl<'a> Iterator for WireIter<'a> {

    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.total.iter().sum() {
            return None;
        }

        let mut buf = vec![0u8; DNS_HEADER_LEN];

        buf.splice(0..2, self.message.id.to_be_bytes());

        let flags = (if self.message.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.message.op_code as u16 & 0x0F) << 11) |  // Opcode
            (if self.message.authoritative { 0x0400 } else { 0 }) |  // AA bit
            0 |  // TC bit
            (if self.message.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.message.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.message.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.message.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.message.response_code as u16 & 0x000F);  // RCODE

        buf.splice(2..4, flags.to_be_bytes());

        buf.splice(4..6, (self.message.queries.len() as u16).to_be_bytes());

        let mut compression_data = HashMap::new();
        let mut off = DNS_HEADER_LEN;
        let mut truncated = false;

        for query in &self.message.queries {
            let q = query.to_bytes(&mut compression_data, off);
            if off+q.len() > self.max_payload_len {
                truncated = true;
                break;
            }

            buf.extend_from_slice(&q);
            off += q.len();
        }

        if !truncated {
            let mut total = 0;
            for (i, records) in self.message.sections.iter().enumerate() {
                let before = total;
                total += self.total[i];

                if self.position < total {
                    let (records, count, t) = records_to_bytes(off, &records[self.position - before..], &mut compression_data, self.max_payload_len);
                    buf.extend_from_slice(&records);
                    buf.splice(i*2+6..i*2+8, count.to_be_bytes());
                    self.position += count as usize;

                    if t {
                        break;
                    }
                }
            }
        }

        Some(buf)
    }
}

fn records_from_bytes(buf: &[u8], off: &mut usize, count: u16) -> Result<Vec<RRName>, MessageError> {
    let mut section = Vec::new();

    for _ in 0..count {
        let (fqdn, length) = unpack_fqdn(buf, *off);
        *off += length;

        let _type = RRTypes::try_from(u16::from_be_bytes([buf[*off], buf[*off+1]])).map_err(|e| MessageError::RecordError(e.to_string()))?;

        match _type {
            RRTypes::TKey => {}
            RRTypes::TSig => {}
            RRTypes::Opt => {
                let record = <dyn RecordBase>::from_wire(_type, buf, *off+2).map_err(|e| MessageError::RecordError(e.to_string()))?;
            }
            RRTypes::Any => {}
            _ => {
                let class = u16::from_be_bytes([buf[*off+2], buf[*off+3]]);
                let cache_flush = (class & 0x8000) != 0;
                let class = RRClasses::try_from(class & 0x7FFF).map_err(|e| MessageError::RecordError(e.to_string()))?;
                let ttl = u32::from_be_bytes([buf[*off+4], buf[*off+5], buf[*off+6], buf[*off+7]]);

                let record = <dyn RecordBase>::from_wire(_type, buf, *off+8).map_err(|e| MessageError::RecordError(e.to_string()))?;

                let index = match section.iter().position(|name: &RRName| fqdn.eq(name.get_fqdn())) {
                    Some(i) => i,
                    None => {
                        section.push(RRName::new(&fqdn));
                        section.len() - 1
                    }
                };

                match section[index]
                        .get_sets_mut() //I DONT LIKE HAVING TO MUT SEARCH BUT WHATEVER...
                        .iter_mut()
                        .find(|s| s.get_type().eq(&_type) && s.get_class().eq(&class)) {
                    Some(set) => {
                        set.add_record(ttl, record);
                    }
                    None => {
                        let mut set = RRSet::new(_type, class, ttl);
                        set.add_record(ttl, record);
                        section[index].add_set(set);
                    }
                }
            }
        }

        *off += 10+u16::from_be_bytes([buf[*off+8], buf[*off+9]]) as usize;
    }

    Ok(section)
}

fn records_to_bytes(off: usize, section: &[RRName], compression_data: &mut HashMap<String, usize>, max_payload_len: usize) -> (Vec<u8>, u16, bool) {
    let mut truncated = false;

    let mut buf = Vec::new();
    let mut i = 0;
    let mut off = off;

    for name in section.iter() {
        let fqdn = pack_fqdn(name.get_fqdn(), compression_data, off, true);

        for set in name.get_sets() {
            let class = set.get_class().get_code().to_be_bytes();
            let ttl = set.get_ttl().to_be_bytes();

            for record in set.get_records() {
                off += fqdn.len()+8;

                match record.to_bytes(compression_data, off) {
                    Ok(r) => {
                        if off+r.len() > max_payload_len {
                            truncated = true;
                            break;
                        }

                        buf.extend_from_slice(&fqdn);
                        buf.extend_from_slice(&record.get_type().get_code().to_be_bytes());

                        buf.extend_from_slice(&class);
                        buf.extend_from_slice(&ttl);

                        buf.extend_from_slice(&r);
                        off += r.len();
                        i += 1;
                    }
                    Err(_) => continue
                }
            }
        }
    }

    (buf, i, truncated)
}

fn add_record(section: &mut Vec<RRName>, query: &RRQuery, ttl: u32, record: Box<dyn RecordBase>) {
    let fqdn = query.get_fqdn();

    let name = match section.iter_mut().find(|name| fqdn.eq(name.get_fqdn())) {
        Some(n) => n,
        None => {
            section.push(RRName::new(&fqdn));
            section.last_mut().unwrap()
        }
    };

    let _type = query.get_type();
    let class = query.get_class();

    if let Some(set) = name
        .get_sets_mut()
        .iter_mut()
        .find(|s| s.get_type().eq(&_type) && s.get_class().eq(&class))
    {
        set.add_record(ttl, record);
    } else {
        let mut set = RRSet::new(_type, class, ttl);
        set.add_record(ttl, record);
        name.add_set(set);
    }
}
