use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::utils::fqdn_utils::unpack_fqdn;

pub mod inter;
pub mod in_a_rr_data;
pub mod ch_a_rr_data;
pub mod aaaa_rr_data;
pub mod cname_rr_data;
pub mod dnskey_rr_data;
pub mod ds_rr_data;
pub mod svcb_rr_data;
pub mod https_rr_data;
pub mod mx_rr_data;
pub mod ns_rr_data;
pub mod nsec_rr_data;
pub mod nsec3_rr_data;
pub mod nsec3param_rr_data;
pub mod opt_rr_data;
pub mod ptr_rr_data;
pub mod hinfo_rr_data;
pub mod rrsig_rr_data;
pub mod soa_rr_data;
pub mod spf_rr_data;
pub mod srv_rr_data;
pub mod naptr_rr_data;
pub mod tkey_rr_data;
pub mod tsig_rr_data;
pub mod txt_rr_data;
pub mod uri_rr_data;
pub mod loc_rr_data;
pub mod sshfp_rr_data;
pub mod smimea_rr_data;
pub mod any_rr_data;

pub fn get_fqdn_from_data(class: &RRClasses, _type: &RRTypes, data: &[u8]) -> Option<String> {
    match _type {
        RRTypes::A => {
            match class {
                RRClasses::Ch => Some(unpack_fqdn(&data[2..], 0).0),
                _ => None
            }
        }
        RRTypes::Ns | RRTypes::CName | RRTypes::Ptr | RRTypes::NSec | RRTypes::TKey | RRTypes::TSig => Some(unpack_fqdn(&data[2..], 0).0),
        /*
        RRTypes::Soa => {
            /.*
            let (name, consumed) = unpack_fqdn(&self.data[2..], 0);
            let (mailbox, consumed) = unpack_fqdn(&self.data[2..], 0);

            let compressed_name = pack_fqdn_compressed(&name, compression_data, 2+off);

            let mut buf = Vec::with_capacity(self.data.len()+compressed_name.len()-consumed);
            buf.extend_from_slice(&((buf.len()-2) as u16).to_be_bytes());
            //buf.extend_from_slice(&self.data[2..]);
            buf.extend_from_slice(&compressed_name);
            buf.extend_from_slice(&self.data[2 + consumed..]);

            &buf
            *./
        }
        RRTypes::Mx => {

        }
        RRTypes::Srv => {

        }
        RRTypes::RRSig => {

        }

        RRTypes::Svcb | RRTypes::Https => {

        }
        */
        _ => None
    }
}
