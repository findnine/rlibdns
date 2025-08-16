use std::collections::HashMap;
use std::{fmt, io};
use std::fmt::Formatter;
use std::net::SocketAddr;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::records::inter::record_base::RecordBase;
use crate::messages::dns_query::DnsQuery;
use crate::messages::inter::rr_types::RRTypes;
use crate::utils::record_utils::{records_from_bytes, records_to_bytes};
/*
                               1  1  1  1  1  1
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
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
pub struct MessageBase {
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
    queries: Vec<DnsQuery>,
    answers: Vec<(String, Box<dyn RecordBase>)>, //WE HAVE TO SWITCH FROM ORDERED_MAP TO VEC FOR RFC 5936
    authority_records: Vec<(String, Box<dyn RecordBase>)>,
    additional_records: Vec<(String, Box<dyn RecordBase>)>
}

impl Default for MessageBase {

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
            answers: Vec::new(),
            authority_records: Vec::new(),
            additional_records: Vec::new()
        }
    }
}

impl MessageBase {

    pub fn new(id: u16) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        let id = u16::from_be_bytes([buf[0], buf[1]]);

        let flags = u16::from_be_bytes([buf[2], buf[3]]);

        let qr = (flags & 0x8000) != 0;
        let op_code = OpCodes::from_code(((flags >> 11) & 0x0F) as u8).ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        //let z = (flags & 0x0040) != 0;
        let authenticated_data = (flags & 0x0020) != 0;
        let checking_disabled = (flags & 0x0010) != 0;
        let response_code = ResponseCodes::from_code((flags & 0x000F) as u8).ok_or(io::Error::from(io::ErrorKind::InvalidData))?;

        let qd_count = u16::from_be_bytes([buf[4], buf[5]]);
        let an_count = u16::from_be_bytes([buf[6], buf[7]]);
        let ns_count = u16::from_be_bytes([buf[8], buf[9]]);
        let ar_count = u16::from_be_bytes([buf[10], buf[11]]);

        let mut queries = Vec::new();
        let mut off = DNS_HEADER_LEN;

        for _ in 0..qd_count {
            queries.push(DnsQuery::from_bytes(buf, &mut off));
        }

        let answers = records_from_bytes(buf, &mut off, an_count);
        let authority_records = records_from_bytes(buf, &mut off, ns_count);
        let additional_records = records_from_bytes(buf, &mut off, ar_count);

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
            answers,
            authority_records,
            additional_records
        })
    }

    //TRUNCATE WILL BE HANDLED BY ITERATOR...
    pub fn to_bytes(&self, max_payload_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; DNS_HEADER_LEN];

        buf.splice(0..2, self.id.to_be_bytes());

        buf.splice(4..6, (self.queries.len() as u16).to_be_bytes());

        let mut label_map = HashMap::new();
        let mut off = DNS_HEADER_LEN;
        let mut truncated = false;

        for query in &self.queries {
            let q = query.to_bytes(&mut label_map, off);
            if off+q.len() > max_payload_len {
                truncated = true;
                break;
            }

            buf.extend_from_slice(&q);
            off += q.len();
        }

        if !truncated {
            let (records, i, t) = records_to_bytes(off, &self.answers, &mut label_map, max_payload_len);
            buf.extend_from_slice(&records);
            truncated = t;

            buf.splice(6..8, i.to_be_bytes());
        }

        if !truncated {
            let (records, i, t) = records_to_bytes(off, &self.authority_records, &mut label_map, max_payload_len);
            buf.extend_from_slice(&records);
            truncated = t;

            buf.splice(8..10, i.to_be_bytes());
        }

        if !truncated {
            let (records, i, t) = records_to_bytes(off, &self.additional_records, &mut label_map, max_payload_len);
            buf.extend_from_slice(&records);
            truncated = t;

            buf.splice(10..12, i.to_be_bytes());
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

    pub fn to_byte_stream(&self, max_payload_len: usize) -> MessageBaseStreamIter {
        MessageBaseStreamIter {
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

    pub fn add_query(&mut self, query: DnsQuery) {
        self.queries.push(query);
    }

    pub fn get_queries(&self) -> &Vec<DnsQuery> {
        &self.queries
    }

    pub fn get_queries_mut(&mut self) -> &mut Vec<DnsQuery> {
        &mut self.queries
    }

    pub fn has_answers(&self) -> bool {
        !self.answers.is_empty()
    }

    pub fn add_answer(&mut self, query: &str, record: Box<dyn RecordBase>) {
        self.answers.push((query.to_string(), record));
    }

    pub fn get_answers(&self) -> &Vec<(String, Box<dyn RecordBase>)> {
        &self.answers
    }

    pub fn get_answers_mut(&mut self) -> &mut Vec<(String, Box<dyn RecordBase>)> {
        &mut self.answers
    }

    pub fn calculate_total_answers(&self) -> usize {
        self.answers.len()
    }

    pub fn has_authority_records(&self) -> bool {
        !self.authority_records.is_empty()
    }

    pub fn add_authority_record(&mut self, query: &str, record: Box<dyn RecordBase>) {
        self.authority_records.push((query.to_string(), record));
    }

    pub fn get_authority_records(&self) -> &Vec<(String, Box<dyn RecordBase>)> {
        &self.authority_records
    }

    pub fn get_authority_records_mut(&mut self) -> &mut Vec<(String, Box<dyn RecordBase>)> {
        &mut self.authority_records
    }

    pub fn calculate_total_authority_records(&self) -> usize {
        self.authority_records.len()
    }

    pub fn has_additional_records(&self) -> bool {
        !self.additional_records.is_empty()
    }

    pub fn add_additional_record(&mut self, query: &str, record: Box<dyn RecordBase>) {
        self.additional_records.push((query.to_string(), record));
    }

    pub fn get_additional_records(&self) -> &Vec<(String, Box<dyn RecordBase>)> {
        &self.additional_records
    }

    pub fn get_additional_records_mut(&mut self) -> &mut Vec<(String, Box<dyn RecordBase>)> {
        &mut self.additional_records
    }

    pub fn calculate_total_additional_records(&self) -> usize {
        self.additional_records.len()
    }
}

impl fmt::Display for MessageBase {

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
                self.answers.len(),
                self.authority_records.len(),
                self.additional_records.len())?;

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

        if !self.answers.is_empty() {
            writeln!(f, "\r\n;; ANSWER SECTION:")?;
            for (q, r) in self.answers.iter() {
                writeln!(f, "{:<24}{}", format!("{}.", q), r)?;
            }
        }

        if !self.authority_records.is_empty() {
            writeln!(f, "\r\n;; AUTHORITATIVE SECTION:")?;
            for (q, r) in self.authority_records.iter() {
                writeln!(f, "{:<24}{}", format!("{}.", q), r)?;
            }
        }

        if !self.additional_records.is_empty() {
            writeln!(f, "\r\n;; ADDITIONAL SECTION:")?;
            for (q, r) in self.additional_records.iter() {
                if !q.eq("") && !r.get_type().eq(&RRTypes::Opt) {
                    writeln!(f, "{:<24}{}", format!("{}.", q), r)?;
                }
            }
        }

        Ok(())
    }
}

pub struct MessageBaseStreamIter<'a> {
    message: &'a MessageBase,
    position: usize,
    max_payload_len: usize
}

impl<'a> Iterator for MessageBaseStreamIter<'a> {

    type Item = (usize, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.message.calculate_total_answers() + self.message.calculate_total_additional_records() + self.message.calculate_total_authority_records() {
            println!("NONE");
            return None;
        }


        let mut buf = vec![0u8; DNS_HEADER_LEN];

        buf.splice(0..2, self.message.id.to_be_bytes());

        buf.splice(4..6, (self.message.queries.len() as u16).to_be_bytes());

        let mut label_map = HashMap::new();
        let mut off = DNS_HEADER_LEN;
        let mut truncated = false;

        for query in &self.message.queries {
            let q = query.to_bytes(&mut label_map, off);
            if off+q.len() > self.max_payload_len {
                truncated = true;
                break;
            }

            buf.extend_from_slice(&q);
            off += q.len();
        }


        let total = self.message.calculate_total_answers();
        if !truncated && self.position < total {
            let (records, i, t) = records_to_bytes(off, &self.message.answers[self.position..], &mut label_map, self.max_payload_len);
            buf.extend_from_slice(&records);
            truncated = t;
            self.position += i as usize;

            buf.splice(6..8, i.to_be_bytes());
        }

        let mut x = total;
        let total = self.message.calculate_total_authority_records();
        if !truncated && self.position < x + total {
            let (records, i, t) = records_to_bytes(off, &self.message.authority_records[self.position - x..], &mut label_map, self.max_payload_len);
            buf.extend_from_slice(&records);
            truncated = t;
            self.position += i as usize;

            buf.splice(8..10, i.to_be_bytes());
        }

        x += total;
        let total = self.message.calculate_total_additional_records();
        if !truncated && self.position < x + total {
            let (records, i, t) = records_to_bytes(off, &self.message.additional_records[self.position - x..], &mut label_map, self.max_payload_len);
            buf.extend_from_slice(&records);
            truncated = t;
            self.position += i as usize;

            buf.splice(10..12, i.to_be_bytes());
        }

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

        Some((self.position, buf))
    }
}
