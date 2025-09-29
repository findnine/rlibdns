use std::io;
use std::path::PathBuf;
use crate::utils::fqdn_utils::{encode_fqdn, decode_fqdn};
use crate::utils::trie::trie::Trie;
use crate::zone::inter::zone_types::ZoneTypes;
use crate::zone::zone::Zone;
use crate::zone::zone_reader::ZoneReader;

#[derive(Debug, Clone)]
pub struct ZoneStore {
    trie: Trie<Zone>
}

impl ZoneStore {

    pub fn new() -> Self {
        Self {
            trie: Trie::new()
        }
    }

    pub fn open<P: Into<PathBuf>>(&mut self, file_path: P, fqdn: &str) -> io::Result<()> {
        let mut zone = Zone::new(ZoneTypes::Master);

        let mut reader = ZoneReader::open(file_path, fqdn)?;
        for (mut query, ttl, record) in reader.iter() {
            let fqdn = query.get_fqdn();
            match fqdn {
                //"." => self.add_record(record), //BE CAREFUL WITH THIS ONE - DONT ALLOW MOST OF THE TIME
                "@" => {
                    query.set_fqdn("");
                    zone.add_record(&query, ttl, record)
                }
                _ => zone.add_record(&query, ttl, record)/*{
                    match self.trie.get_fqdn_mut(&name) {
                        Some(zone) => zone.add_record(record),
                        None => {
                            let mut zone = Zone::new(ZoneTypes::Master);
                            zone.add_record(record);
                            self.trie.insert_fqdn(&name, zone);
                        }
                    }
                }*/
                //_ => zone.add_record_to(&name, record, ZoneTypes::Master)
            }
        }

        self.trie.insert(encode_fqdn(reader.get_origin()), zone);

        Ok(())
    }

    pub fn open_with_jnl<P: Into<PathBuf>>(&mut self, file_path: P, fqdn: &str, journal_path: P) -> io::Result<()> {
        let mut zone = Zone::new_with_jnl(ZoneTypes::Master, journal_path);

        /*
        let mut reader = ZoneReader::open(file_path, fqdn)?;
        for (name, record) in reader.iter() {
            match name.as_str() {
                //"." => self.add_record(record), //BE CAREFUL WITH THIS ONE - DONT ALLOW MOST OF THE TIME
                "@" => zone.add_record("", record),
                _ => zone.add_record(&name, record)/*{
                    match self.trie.get_fqdn_mut(&name) {
                        Some(zone) => zone.add_record(record),
                        None => {
                            let mut zone = Zone::new(ZoneTypes::Master);
                            zone.add_record(record);
                            self.trie.insert_fqdn(&name, zone);
                        }
                    }
                }*/
                //_ => zone.add_record_to(&name, record, ZoneTypes::Master)
            }
        }

        self.trie.insert(encode_fqdn(reader.get_origin()), zone);
        */

        Ok(())
    }

    pub fn add_zone(&mut self, fqdn: &str, zone: Zone) {
        self.trie.insert(encode_fqdn(fqdn), zone);
    }

    pub fn get_zone_exact(&self, apex: &str) -> Option<&Zone> {
        self.trie.get(&encode_fqdn(apex))
    }

    pub fn get_deepest_zone(&self, name: &str) -> Option<&Zone> {
        self.trie.get_deepest(&encode_fqdn(name)).map(|(_, zone)| zone)
    }

    pub fn get_deepest_zone_with_name(&self, name: &str) -> Option<(String, &Zone)> {
        self.trie.get_deepest(&encode_fqdn(name)).map(|(key, zone)| (decode_fqdn(&key), zone))
    }
}
