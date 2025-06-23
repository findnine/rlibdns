use std::collections::HashMap;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::a_record::ARecord;
use crate::records::aaaa_record::AaaaRecord;
use crate::records::cname_record::CNameRecord;
use crate::records::dnskey_record::DnsKeyRecord;
use crate::records::https_record::HttpsRecord;
use crate::records::inter::record_base::RecordBase;
use crate::records::loc_record::LocRecord;
use crate::records::mx_record::MxRecord;
use crate::records::ns_record::NsRecord;
use crate::records::nsec_record::NSecRecord;
use crate::records::opt_record::OptRecord;
use crate::records::ptr_record::PtrRecord;
use crate::records::rrsig_record::RRSigRecord;
use crate::records::soa_record::SoaRecord;
use crate::records::srv_record::SrvRecord;
use crate::records::txt_record::TxtRecord;
use crate::records::uri_record::UriRecord;
use crate::utils::domain_utils::{pack_domain, unpack_domain};
use crate::utils::ordered_map::OrderedMap;

pub fn records_from_bytes(buf: &[u8], off: &mut usize, count: u16) -> OrderedMap<String, Vec<Box<dyn RecordBase>>> {
    let mut records: OrderedMap<String, Vec<Box<dyn RecordBase>>> = OrderedMap::new();

    for _ in 0..count {
        /*
        let query = match buf[*off] {
            0 => {
                *off += 1;
                String::new()
            }
            _ => {
                let (domain, length) = unpack_domain(buf, *off);
                *off += length;
                domain
            }
        };
        */

        let (query, length) = unpack_domain(buf, *off);
        *off += length;

        let record = match RRTypes::from_code(u16::from_be_bytes([buf[*off], buf[*off+1]])).unwrap() {
            RRTypes::A => ARecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Aaaa =>AaaaRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Ns => NsRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::CName => CNameRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Soa => SoaRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Ptr => PtrRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Mx => MxRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Txt => TxtRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Loc => LocRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Srv => SrvRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Opt => OptRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::RRSig => RRSigRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Nsec => NSecRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::DnsKey => DnsKeyRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Https => HttpsRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Spf => {
                todo!()
            }
            RRTypes::Tsig => {
                todo!()
            }
            RRTypes::Uri => UriRecord::from_bytes(buf, *off+2).upcast(),
            RRTypes::Caa => {
                todo!()
            }
            _ => {
                todo!()
            }
        };

        records.entry(query).or_insert_with(Vec::new).push(record);
        *off += 10+u16::from_be_bytes([buf[*off+8], buf[*off+9]]) as usize;
    }

    records
}

pub fn records_to_bytes(off: usize, records: &OrderedMap<String, Vec<Box<dyn RecordBase>>>, label_map: &mut HashMap<String, usize>, max_payload_len: usize) -> (Vec<u8>, u16, bool) {
    let mut truncated = false;
    
    let mut buf = Vec::new();
    let mut i = 0;
    let mut off = off;

    'outer: for (query, records) in records.iter() {
        for record in records {
            match record.to_bytes(label_map, off) {
                Ok(r) => {
                    let q = pack_domain(query, label_map, off, true);

                    let len = q.len()+r.len();

                    if off+len > max_payload_len {
                        truncated = true;
                        break 'outer;
                    }

                    buf.extend_from_slice(&q);
                    buf.extend_from_slice(&r);
                    off += len;
                    i += 1;
                }
                Err(_) => continue
            }
        }
    }

    (buf, i, truncated)
}
