use std::path::PathBuf;
use crate::journal::journal_reader::ErrorKind;
use crate::messages::inter::rr_classes::RRClasses;
use crate::utils::fqdn_utils::{encode_fqdn, decode_fqdn};
use crate::utils::trie::trie::Trie;
use crate::zone::inter::zone_types::ZoneTypes;
use crate::zone::zone::Zone;
use crate::zone::zone_reader::{ZoneReader, ZoneReaderError};

#[derive(Debug, Clone)]
pub struct ZoneStore {
    trie: Trie<Vec<Zone>>
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZoneError(String);

impl ZoneStore {

    pub fn new() -> Self {
        Self {
            trie: Trie::new()
        }
    }

    pub fn open<P: Into<PathBuf>>(&mut self, file_path: P, fqdn: &str, class: RRClasses) -> Result<(), ZoneReaderError> {
        let mut zone = Zone::new(ZoneTypes::Master, class);

        let mut reader = ZoneReader::open(file_path, fqdn, class)?;

        for record in reader.records() {
            match record {
                Ok((query, ttl, record)) => {
                    zone.add_record(&query, ttl, record);
                }
                Err(e) => {
                    println!("{}", e);
                }
            }
        }

        let key = encode_fqdn(reader.get_origin());
        match self.trie.get_mut(&key) {
            Some(zones) => {
                if zones.iter().any(|z| z.get_class().eq(&class)) {
                    return Ok(());
                }
                zones.push(zone);
            }
            None => {
                self.trie.insert(key, vec![zone]);
            }
        }

        Ok(())
    }

    pub fn open_with_jnl<P: Into<PathBuf>>(&mut self, file_path: P, fqdn: &str, class: RRClasses, journal_path: P) -> Result<(), ZoneReaderError> {
        let mut zone = Zone::new_with_jnl(ZoneTypes::Master, class, journal_path);

        let mut reader = ZoneReader::open(file_path, fqdn, class)?;
        for record in reader.records() {
            match record {
                Ok((query, ttl, record)) => {
                    zone.add_record(&query, ttl, record);
                }
                Err(e) => {
                    println!("{}", e);
                }
            }
        }

        let key = encode_fqdn(reader.get_origin());
        match self.trie.get_mut(&key) {
            Some(zones) => {
                if zones.iter().any(|z| z.get_class().eq(&class)) {
                    return Ok(());
                }
                zones.push(zone);
            }
            None => {
                self.trie.insert(key, vec![zone]);
            }
        }

        Ok(())
    }

    pub fn add_zone(&mut self, fqdn: &str, zone: Zone) -> Option<Zone> {
        let key = encode_fqdn(fqdn);
        match self.trie.get_mut(&key) {
            Some(zones) => {
                let class = zone.get_class();
                match zones.iter().find(|z| z.get_class().eq(&class)) {
                    Some(zone) => {

                    }
                    None => {}
                }
                zones.push(zone);
            }
            None => {
                self.trie.insert(key, vec![zone]);
                None
            }
        }
    }

    pub fn remove_zone(&mut self, fqdn: &str, class: RRClasses) {
        //NEEDS REWORK NOW THAT CLASSES ARE INTRODUCED...
        //self.trie.remove(&encode_fqdn(fqdn));
    }

    pub fn get_zone_exact(&self, apex: &str, class: &RRClasses) -> Option<&Zone> {
        self.trie.get(&encode_fqdn(apex))?.iter().find(|z| z.get_class().eq(class))
    }

    pub fn get_zone_exact_mut(&mut self, apex: &str, class: &RRClasses) -> Option<&mut Zone> {
        self.trie.get_mut(&encode_fqdn(apex))?.iter_mut().find(|z| z.get_class().eq(class))
    }

    pub fn get_deepest_zone(&self, name: &str, class: &RRClasses) -> Option<(String, &Zone)> {
        let (key, zones) = self.trie.get_deepest(&encode_fqdn(name))?;
        Some((decode_fqdn(&key), zones.iter().find(|z| z.get_class().eq(class))?))
    }

    pub fn get_deepest_zone_mut(&mut self, name: &str, class: &RRClasses) -> Option<(String, &mut Zone)> {
        let (key, zones) = self.trie.get_deepest_mut(&encode_fqdn(name))?;
        Some((decode_fqdn(&key), zones.iter_mut().find(|z| z.get_class().eq(class))?))
    }
}
