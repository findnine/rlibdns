use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::SocketAddr;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::messages::inter::rr_classes::RRClasses;
use crate::rr_data::inter::rr_data::RRData;
use crate::messages::rr_query::RRQuery;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::opt_rr_data::OptRRData;
use crate::utils::fqdn_utils::{pack_fqdn_compressed, unpack_fqdn};
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

pub type MessageRecord = (String, RRClasses, u32, Box<dyn RRData>);

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
    sections: [Vec<MessageRecord>; 3],
    option: Option<OpCodes>
}

impl Default for Message {

    fn default() -> Self {
        Self {
            id: 0,
            op_code: Default::default(),
            response_code: Default::default(),
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
            queries.push(RRQuery::from_bytes(buf, &mut off)?);
        }

        let sections = [
            section_from_wire(buf, &mut off, u16::from_be_bytes([buf[6], buf[7]]))?,
            section_from_wire(buf, &mut off, u16::from_be_bytes([buf[8], buf[9]]))?,
            section_from_wire(buf, &mut off, u16::from_be_bytes([buf[10], buf[11]]))?
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
        let mut buf = Vec::with_capacity(max_payload_len);

        //SURE ITS UNSAFE BUT I DONT THINK THERE IS ANY WAY FOR THIS TO TRIGGER UNLESS MAX PAYLOAD IS LESS THAN 12...
        unsafe { buf.set_len(DNS_HEADER_LEN) };

        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[4..6].copy_from_slice(&(self.queries.len() as u16).to_be_bytes());

        let mut compression_data = HashMap::new();
        let mut off = DNS_HEADER_LEN;
        let mut truncated = false;

        for query in &self.queries {
            let q = query.to_bytes_compressed(&mut compression_data, off);
            if off+q.len() > max_payload_len {
                truncated = true;
                break;
            }

            buf.extend_from_slice(&q);
            off += q.len();
        }

        if !truncated {
            for (i, section) in self.sections.iter().enumerate() {
                let (records, count, t) = section_to_wire(&mut compression_data, off, section, max_payload_len);
                buf.extend_from_slice(&records);
                buf[i*2+6..i*2+8].copy_from_slice(&count.to_be_bytes());

                if t {
                    truncated = t;
                    break;
                }
            }
        }

        let flags = (if self.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.op_code.get_code() as u16 & 0x0F) << 11) |  // Opcode
            (if self.authoritative { 0x0400 } else { 0 }) |  // AA bit
            (if truncated { 0x0200 } else { 0 }) |  // TC bit
            (if self.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.response_code.get_code() as u16 & 0x000F);  // RCODE

        buf[2..4].copy_from_slice(&flags.to_be_bytes());

        buf
    }

    pub fn wire_chunks(&self, max_payload_len: usize) -> WireIter {
        WireIter {
            message: self,
            position: 0,
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

    pub fn set_section(&mut self, index: usize, section: Vec<MessageRecord>) {
        self.sections[index] = section;
    }

    pub fn add_section(&mut self, index: usize, query: &str, class: RRClasses, ttl: u32, data: Box<dyn RRData>) {
        self.sections[index].push((query.to_string(), class, ttl, data));
    }

    pub fn get_section(&self, index: usize) -> &Vec<MessageRecord> {
        self.sections[index].as_ref()
    }

    pub fn get_section_mut(&mut self, index: usize) -> &mut Vec<MessageRecord> {
        self.sections[index].as_mut()
    }

    pub fn total_section(&self, index: usize) -> usize {
        self.sections[index].len()
    }

    pub fn set_sections(&mut self, section: [Vec<MessageRecord>; 3]) {
        self.sections = section;
    }

    pub fn get_sections(&self) -> &[Vec<MessageRecord>; 3] {
        &self.sections
    }

    pub fn get_sections_mut(&mut self) -> &mut [Vec<MessageRecord>; 3] {
        &mut self.sections
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

            for (fqdn, class, ttl, record) in self.sections[0].iter() {
                writeln!(f, "{:<24}{:<8}{:<8}{}", format!("{}.", fqdn), ttl, class.to_string(), record)?;
            }
        }

        if !self.sections[1].is_empty() {
            writeln!(f, "\r\n;; AUTHORITATIVE SECTION:")?;

            for (fqdn, class, ttl, record) in self.sections[1].iter() {
                writeln!(f, "{:<24}{:<8}{:<8}{}", format!("{}.", fqdn), ttl, class.to_string(), record)?;
            }
        }

        if !self.sections[2].is_empty() {
            writeln!(f, "\r\n;; ADDITIONAL SECTION:")?;

            for (fqdn, class, ttl, record) in self.sections[2].iter() {
                writeln!(f, "{:<24}{:<8}{:<8}{}", format!("{}.", fqdn), ttl, class.to_string(), record)?;
            }
        }

        Ok(())
    }
}

pub struct WireIter<'a> {
    message: &'a Message,
    position: usize,
    max_payload_len: usize
}

impl<'a> Iterator for WireIter<'a> {

    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.message.sections.iter().map(|r| r.len()).sum() {
            return None;
        }


        let mut buf = Vec::with_capacity(self.max_payload_len);

        //SURE ITS UNSAFE BUT I DONT THINK THERE IS ANY WAY FOR THIS TO TRIGGER UNLESS MAX PAYLOAD IS LESS THAN 12...
        unsafe { buf.set_len(DNS_HEADER_LEN) };

        buf[0..2].copy_from_slice(&self.message.id.to_be_bytes());

        let flags = (if self.message.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.message.op_code.get_code() as u16 & 0x0F) << 11) |  // Opcode
            (if self.message.authoritative { 0x0400 } else { 0 }) |  // AA bit
            0 |  // TC bit
            (if self.message.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.message.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.message.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.message.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.message.response_code.get_code() as u16 & 0x000F);  // RCODE

        buf[2..4].copy_from_slice(&flags.to_be_bytes());

        buf[4..6].copy_from_slice(&(self.message.queries.len() as u16).to_be_bytes());

        let mut compression_data = HashMap::new();
        let mut off = DNS_HEADER_LEN;
        let mut truncated = false;

        for query in &self.message.queries {
            let q = query.to_bytes_compressed(&mut compression_data, off);
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
                total += self.message.sections[i].len();

                if self.position < total {
                    let (records, count, t) = section_to_wire(&mut compression_data, off, &records[self.position - before..], self.max_payload_len);
                    buf.extend_from_slice(&records);
                    buf[i*2+6..i*2+8].copy_from_slice(&count.to_be_bytes());
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

fn section_from_wire(buf: &[u8], off: &mut usize, count: u16) -> Result<Vec<MessageRecord>, MessageError> {
    let mut section = Vec::new();

    for _ in 0..count {
        let (fqdn, length) = unpack_fqdn(buf, *off);
        *off += length;

        let _type = RRTypes::try_from(u16::from_be_bytes([buf[*off], buf[*off+1]])).map_err(|e| MessageError::RecordError(e.to_string()))?;

        match _type {
            RRTypes::TKey => {}
            RRTypes::TSig => {}
            RRTypes::Opt => {
                let data = OptRRData::from_bytes(buf, *off+2).map_err(|e| MessageError::RecordError(e.to_string()))?;
                *off += 5+u16::from_be_bytes([buf[*off+3], buf[*off+4]]) as usize;
            }
            _ => {
                let class = u16::from_be_bytes([buf[*off+2], buf[*off+3]]);
                let cache_flush = (class & 0x8000) != 0;
                let class = RRClasses::try_from(class & 0x7FFF).map_err(|e| MessageError::RecordError(e.to_string()))?;
                let ttl = u32::from_be_bytes([buf[*off+4], buf[*off+5], buf[*off+6], buf[*off+7]]);

                let data = <dyn RRData>::from_wire(_type, &class, buf, *off+8).map_err(|e| MessageError::RecordError(e.to_string()))?;
                section.push((fqdn, class, ttl, data));
                *off += 10+u16::from_be_bytes([buf[*off+8], buf[*off+9]]) as usize;
            }
        }
    }

    Ok(section)
}

fn section_to_wire(compression_data: &mut HashMap<String, usize>, off: usize, section: &[MessageRecord], max_payload_len: usize) -> (Vec<u8>, u16, bool) {
    let mut truncated = false;

    let mut buf = Vec::new();
    let mut i = 0;
    let mut off = off;

    for (fqdn, class, ttl, data) in section.iter() {
        let fqdn = pack_fqdn_compressed(&fqdn, compression_data, off);

        off += fqdn.len()+8;

        match data.to_wire(compression_data, off) {
            Ok(r) => {
                if off+r.len() > max_payload_len {
                    truncated = true;
                    break;
                }

                buf.extend_from_slice(&fqdn);
                buf.extend_from_slice(&data.get_type().get_code().to_be_bytes());

                buf.extend_from_slice(&class.get_code().to_be_bytes());
                buf.extend_from_slice(&ttl.to_be_bytes());

                buf.extend_from_slice(&r);
                off += r.len();
                i += 1;
            }
            Err(_) => continue
        }
    }

    (buf, i, truncated)
}
