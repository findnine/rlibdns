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

pub trait ZoneRecordData: RecordBase {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError>;

    fn upcast(self) -> Box<dyn ZoneRecordData>;
}

impl dyn ZoneRecordData {

    pub fn new(_type: RRTypes, class: &RRClasses) -> Option<Box<dyn ZoneRecordData>> {
        Some(match _type {
            RRTypes::A      => {
                match class {
                    RRClasses::Ch => <ChARecord as ZoneRecordData>::upcast(ChARecord::default()),
                    _ => <InARecord as ZoneRecordData>::upcast(InARecord::default())
                }
            }
            RRTypes::Aaaa   => <AaaaRecord as ZoneRecordData>::upcast(AaaaRecord::default()),
            RRTypes::Ns     => <NsRecord as ZoneRecordData>::upcast(NsRecord::default()),
            RRTypes::CName  => <CNameRecord as ZoneRecordData>::upcast(CNameRecord::default()),
            RRTypes::Soa    => <SoaRecord as ZoneRecordData>::upcast(SoaRecord::default()),
            //RRTypes::Ptr    => <PtrRecord as ZoneRecordData>::upcast(PtrRecord::default()),
            //RRTypes::HInfo  => <HInfoRecord as ZoneRecordData>::upcast(HInfoRecord::default()),
            //RRTypes::Mx     => <MxRecord as ZoneRecordData>::upcast(MxRecord::default()),
            //RRTypes::Txt    => <TxtRecord as ZoneRecordData>::upcast(TxtRecord::default()),
            //RRTypes::Loc    => <LocRecord as ZoneRecordData>::upcast(LocRecord::default()),
            //RRTypes::Srv    => <SrvRecord as ZoneRecordData>::upcast(SrvRecord::default()),
            //RRTypes::Naptr  => <NaptrRecord as ZoneRecordData>::upcast(NaptrRecord::default()),
            //RRTypes::SshFp  => <SshFpRecord as ZoneRecordData>::upcast(SshFpRecord::default()),
            //RRTypes::RRSig  => <RRSigRecord as ZoneRecordData>::upcast(RRSigRecord::default()),
            //RRTypes::Nsec   => <NSecRecord as ZoneRecordData>::upcast(NSecRecord::default()),
            //RRTypes::DnsKey => <DnsKeyRecord as ZoneRecordData>::upcast(DnsKeyRecord::default()),
            //RRTypes::Smimea => <SmimeaRecord as ZoneRecordData>::upcast(SmimeaRecord::default()),
            //RRTypes::Svcb   => <SvcbRecord as ZoneRecordData>::upcast(SvcbRecord::default()),
            //RRTypes::Https  => <HttpsRecord as ZoneRecordData>::upcast(HttpsRecord::default()),
            /*
            RRTypes::Spf => {
                todo!()
            }*/
            //RRTypes::TKey   => <TKeyRecord as ZoneRecordData>::upcast(TKeyRecord::default()),
            //RRTypes::TSig   => <TSigRecord as ZoneRecordData>::upcast(TSigRecord::default()),
            //RRTypes::Uri    => <UriRecord as ZoneRecordData>::upcast(UriRecord::default()),
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
