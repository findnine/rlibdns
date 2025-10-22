use crate::rr_data::{
    in_a_rr_data::InARRData,
    ch_a_rr_data::ChARRData,
    aaaa_rr_data::AaaaRRData,
    cname_rr_data::CNameRRData,
    dnskey_rr_data::DnsKeyRRData,
    ds_rr_data::DsRRData,
    hinfo_rr_data::HInfoRRData,
    https_rr_data::HttpsRRData,
    loc_rr_data::LocRRData,
    mx_rr_data::MxRRData,
    naptr_rr_data::NaptrRRData,
    ns_rr_data::NsRRData,
    nsec_rr_data::NSecRRData,
    nsec3_rr_data::NSec3RRData,
    nsec3param_rr_data::NSec3ParamRRData,
    ptr_rr_data::PtrRRData,
    rrsig_rr_data::RRSigRRData,
    smimea_rr_data::SmimeaRRData,
    soa_rr_data::SoaRRData,
    srv_rr_data::SrvRRData,
    tkey_rr_data::TKeyRRData,
    tsig_rr_data::TSigRRData,
    sshfp_rr_data::SshFpRRData,
    svcb_rr_data::SvcbRRData,
    txt_rr_data::TxtRRData,
    uri_rr_data::UriRRData
};

use std::any::Any;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::wire::{FromWireLen, ToWire};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RRDataError(pub String);

impl Display for RRDataError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait RRData: Display + Debug + Send + Sync + FromWireLen + ToWire {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> where Self: Sized;

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError>;

    fn upcast(self) -> Box<dyn RRData>;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;
    
    fn clone_box(&self) -> Box<dyn RRData>;

    fn eq_box(&self, other: &dyn RRData) -> bool;
}

impl Clone for Box<dyn RRData> {
    
    fn clone(&self) -> Box<dyn RRData> {
        self.clone_box()
    }
}

impl PartialEq for dyn RRData {

    fn eq(&self, other: &Self) -> bool {
        self.eq_box(other)
    }
}
impl Eq for dyn RRData {}

impl dyn RRData {

    pub fn new(rtype: &RRTypes, class: &RRClasses) -> Option<Box<dyn RRData>> {
        Some(match rtype {
            RRTypes::A      => {
                match class {
                    RRClasses::Ch => ChARRData::default().upcast(),
                    _ => InARRData::default().upcast()
                }
            }
            RRTypes::Aaaa   => AaaaRRData::default().upcast(),
            RRTypes::Ns     => NsRRData::default().upcast(),
            RRTypes::CName  => CNameRRData::default().upcast(),
            RRTypes::Soa    => SoaRRData::default().upcast(),
            RRTypes::Ptr    => PtrRRData::default().upcast(),
            RRTypes::HInfo  => HInfoRRData::default().upcast(),
            RRTypes::Mx     => MxRRData::default().upcast(),
            RRTypes::Txt    => TxtRRData::default().upcast(),
            RRTypes::Loc    => LocRRData::default().upcast(),
            RRTypes::Srv    => SrvRRData::default().upcast(),
            RRTypes::Naptr  => NaptrRRData::default().upcast(),
            RRTypes::Ds     => DsRRData::default().upcast(),
            RRTypes::SshFp  => SshFpRRData::default().upcast(),
            RRTypes::RRSig  => RRSigRRData::default().upcast(),
            RRTypes::NSec   => NSecRRData::default().upcast(),
            RRTypes::DnsKey => DnsKeyRRData::default().upcast(),
            RRTypes::NSec3   => NSec3RRData::default().upcast(),
            RRTypes::NSec3Param  => NSec3ParamRRData::default().upcast(),
            RRTypes::Smimea => SmimeaRRData::default().upcast(),
            RRTypes::Svcb   => SvcbRRData::default().upcast(),
            RRTypes::Https  => HttpsRRData::default().upcast(),
            /*
            RRTypes::Spf => {
                todo!()
            }*/
            RRTypes::TKey   => TKeyRRData::default().upcast(),
            RRTypes::TSig   => TSigRRData::default().upcast(),
            RRTypes::Uri    => UriRRData::default().upcast(),
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
}
