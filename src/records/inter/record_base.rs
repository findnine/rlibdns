use crate::records::{
    a_record::ARecord,
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
    tkey_record::TKeyRecord,
    tsig_record::TSigRecord,
    sshfp_record::SshFpRecord,
    svcb_record::SvcbRecord,
    txt_record::TxtRecord,
    opt_record::OptRecord,
    uri_record::UriRecord
};

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecordError(pub String);

impl Display for RecordError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait RecordBase: Display + Debug + Send + Sync {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> where Self: Sized;

    fn to_bytes(&self, compression_data: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, RecordError>;

    fn get_type(&self) -> RRTypes;

    fn upcast(self) -> Box<dyn RecordBase>;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;
    
    fn clone_box(&self) -> Box<dyn RecordBase>;
}

impl Clone for Box<dyn RecordBase> {
    
    fn clone(&self) -> Box<dyn RecordBase> {
        self.clone_box()
    }
}

impl dyn RecordBase {

    pub fn new(_type: RRTypes) -> Option<Box<dyn RecordBase>> {
        Some(match _type {
            RRTypes::A      => ARecord::default().upcast(),
            RRTypes::Aaaa   => AaaaRecord::default().upcast(),
            RRTypes::Ns     => NsRecord::default().upcast(),
            RRTypes::CName  => CNameRecord::default().upcast(),
            RRTypes::Soa    => SoaRecord::default().upcast(),
            RRTypes::Ptr    => PtrRecord::default().upcast(),
            RRTypes::HInfo  => HInfoRecord::default().upcast(),
            RRTypes::Mx     => MxRecord::default().upcast(),
            RRTypes::Txt    => TxtRecord::default().upcast(),
            RRTypes::Loc    => LocRecord::default().upcast(),
            RRTypes::Srv    => SrvRecord::default().upcast(),
            RRTypes::Naptr  => NaptrRecord::default().upcast(),
            RRTypes::SshFp  => SshFpRecord::default().upcast(),
            RRTypes::RRSig  => RRSigRecord::default().upcast(),
            RRTypes::Nsec   => NSecRecord::default().upcast(),
            RRTypes::DnsKey => DnsKeyRecord::default().upcast(),
            RRTypes::Smimea => SmimeaRecord::default().upcast(),
            RRTypes::Svcb   => SvcbRecord::default().upcast(),
            RRTypes::Https  => HttpsRecord::default().upcast(),
            /*
            RRTypes::Spf => {
                todo!()
            }*/
            RRTypes::TKey   => TKeyRecord::default().upcast(),
            RRTypes::TSig   => TSigRecord::default().upcast(),
            RRTypes::Uri    => UriRecord::default().upcast(),
            /*RRTypes::Caa => {
                todo!()
            }
            _ => {
                todo!()
            }
            */
            // pseudo/unsupported types:
            _ => return None
        })
    }

    pub fn from_wire(_type: RRTypes, buf: &[u8], off: usize) -> Result<Box<dyn RecordBase>, RecordError> {
        Ok(match _type {
            RRTypes::A      => ARecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Aaaa   => AaaaRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Ns     => NsRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::CName  => CNameRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Soa    => SoaRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Ptr    => PtrRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::HInfo  => HInfoRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Mx     => MxRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Txt    => TxtRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Loc    => LocRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Srv    => SrvRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Naptr  => NaptrRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::SshFp  => SshFpRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::RRSig  => RRSigRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Nsec   => NSecRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::DnsKey => DnsKeyRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Smimea => SmimeaRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Svcb   => SvcbRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Https  => HttpsRecord::from_bytes(buf, off)?.upcast(),
            /*
            RRTypes::Spf => {
                todo!()
            }*/
            RRTypes::TKey   => TKeyRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::TSig   => TSigRecord::from_bytes(buf, off)?.upcast(),
            RRTypes::Uri    => UriRecord::from_bytes(buf, off)?.upcast(),
            /*RRTypes::Caa => {
                todo!()
            }
            _ => {
                todo!()
            }
            */
            RRTypes::Opt => OptRecord::from_bytes(buf, off)?.upcast(),
            _ => return Err(RecordError("rrtype could not produce a record".to_string()))
        })
    }
}
