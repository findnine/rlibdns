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
    tkey_record::TKeyRecord,
    tsig_record::TSigRecord,
    sshfp_record::SshFpRecord,
    svcb_record::SvcbRecord,
    txt_record::TxtRecord,
    opt_record::OptRecord,
    uri_record::UriRecord,
    any_record::AnyRecord
};

use crate::records::inter::record_base::RecordBase;
use crate::zone::zone_reader::ZoneReaderError;

pub trait ZoneRecord: RecordBase {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError>;

    fn upcast(self) -> Box<dyn ZoneRecord>;
}

impl dyn ZoneRecord {

    pub fn new(_type: RRTypes, class: &RRClasses) -> Option<Box<dyn ZoneRecord>> {
        Some(match _type {
            RRTypes::A      => {
                match class {
                    RRClasses::Ch => <ChARecord as ZoneRecord>::upcast(ChARecord::default()),
                    _ => <InARecord as ZoneRecord>::upcast(InARecord::default())
                }
            }
            RRTypes::Aaaa   => <AaaaRecord as ZoneRecord>::upcast(AaaaRecord::default()),
            RRTypes::Ns     => <NsRecord as ZoneRecord>::upcast(NsRecord::default()),
            RRTypes::CName  => <CNameRecord as ZoneRecord>::upcast(CNameRecord::default()),
            RRTypes::Soa    => <SoaRecord as ZoneRecord>::upcast(SoaRecord::default()),
            RRTypes::Ptr    => <PtrRecord as ZoneRecord>::upcast(PtrRecord::default()),
            RRTypes::HInfo  => <HInfoRecord as ZoneRecord>::upcast(HInfoRecord::default()),
            RRTypes::Mx     => <MxRecord as ZoneRecord>::upcast(MxRecord::default()),
            RRTypes::Txt    => <TxtRecord as ZoneRecord>::upcast(TxtRecord::default()),
            RRTypes::Loc    => <LocRecord as ZoneRecord>::upcast(LocRecord::default()),
            RRTypes::Srv    => <SrvRecord as ZoneRecord>::upcast(SrvRecord::default()),
            RRTypes::Naptr  => <NaptrRecord as ZoneRecord>::upcast(NaptrRecord::default()),
            RRTypes::SshFp  => <SshFpRecord as ZoneRecord>::upcast(SshFpRecord::default()),
            RRTypes::RRSig  => <RRSigRecord as ZoneRecord>::upcast(RRSigRecord::default()),
            //RRTypes::Nsec   => <NSecRecord as ZoneRecord>::upcast(NSecRecord::default()),
            //RRTypes::DnsKey => <DnsKeyRecord as ZoneRecord>::upcast(DnsKeyRecord::default()),
            RRTypes::Smimea => <SmimeaRecord as ZoneRecord>::upcast(SmimeaRecord::default()),
            RRTypes::Svcb   => <SvcbRecord as ZoneRecord>::upcast(SvcbRecord::default()),
            RRTypes::Https  => <HttpsRecord as ZoneRecord>::upcast(HttpsRecord::default()),
            /*
            RRTypes::Spf => {
                todo!()
            }*/
            //RRTypes::TKey   => <TKeyRecord as ZoneRecord>::upcast(TKeyRecord::default()),
            //RRTypes::TSig   => <TSigRecord as ZoneRecord>::upcast(TSigRecord::default()),
            RRTypes::Uri    => <UriRecord as ZoneRecord>::upcast(UriRecord::default()),
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
