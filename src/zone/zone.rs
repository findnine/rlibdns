use std::path::PathBuf;
use crate::journal::journal_reader::{JournalReader, JournalReaderError};
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::zone::rr_set::RRSet;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{decode_fqdn, encode_fqdn};
use crate::utils::trie::trie::Trie;
use crate::zone::inter::zone_types::ZoneTypes;

#[derive(Debug, Clone)]
pub struct Zone {
    _type: ZoneTypes,
    class: RRClasses,
    rrmap: Trie<Vec<RRSet>>,
    journal_path: Option<PathBuf>
}

impl Default for Zone {

    fn default() -> Self {
        Self {
            _type: Default::default(),
            class: Default::default(),
            rrmap: Trie::new(),
            journal_path: None
        }
    }
}

impl Zone {

    pub fn new(_type: ZoneTypes, class: RRClasses) -> Self {
        Self {
            _type,
            class,
            ..Default::default()
        }
    }

    pub fn new_with_jnl<P: Into<PathBuf>>(_type: ZoneTypes, class: RRClasses, journal_path: P) -> Self {
        Self {
            _type,
            class,
            journal_path: Some(journal_path.into()),
            ..Default::default()
        }
    }

    pub fn set_type(&mut self, _type: ZoneTypes) {
        self._type = _type;
    }

    pub fn get_type(&self) -> ZoneTypes {
        self._type
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn is_authority(&self) -> bool {
        self._type.eq(&ZoneTypes::Master) || self._type.eq(&ZoneTypes::Slave)
    }

    pub fn add_record(&mut self, query: &str, ttl: u32, record: Box<dyn RecordBase>) {
        let key = encode_fqdn(query);
        let _type = record.get_type();

        match self.rrmap.get_mut(&key) {
            Some(sets) => {
                match sets
                        .iter_mut()
                        .find(|s| s.get_type().eq(&_type)) {
                    Some(set) => {
                        set.add_record(ttl, record);
                    }
                    None => {
                        let mut set = RRSet::new(_type, ttl);
                        set.add_record(ttl, record);
                        sets.push(set);
                    }
                }
            }
            None => {
                let mut set = RRSet::new(_type, ttl);
                set.add_record(ttl, record);
                self.rrmap.insert(key, vec![set]);
            }
        }
    }

    pub fn remove_record(&mut self) {
        println!("REMOVE RECORD");
    }

    pub fn remove_set(&mut self, query: &str, _type: &RRTypes) -> Option<RRSet> {
        let key = encode_fqdn(query);

        let (removed, became_empty) = {
            let sets = self.rrmap.get_mut(&key)?;
            let idx = sets.iter().position(|s| s.get_type().eq(_type))?;
            let removed = sets.swap_remove(idx);
            (Some(removed), sets.is_empty())
        };

        if became_empty {
            self.rrmap.remove(&key);
        }

        removed
    }

    pub fn remove_all_records(&mut self, query: &str) {
        println!("REMOVE ALL RECORD");
    }
    /*
    pub fn add_record(&mut self, name: &str, record: Box<dyn RecordBase>) {
        let key = encode_fqdn(name);
        match self.records.get_mut(&key) {
            Some(records) => {
                records.entry(record.get_type()).or_insert(Vec::new()).push(record);
            }
            None => {
                let mut rrmap = BTreeMap::new();
                rrmap.insert(record.get_type(), vec![record]);
                self.records.insert(key, rrmap);
            }
        }

        //self.records
        //    .entry(name.to_string()).or_insert_with(IndexMap::new)
        //    .entry(record.get_type()).or_insert(Vec::new()).push(record);

        //UPDATE SOA
        //ADD TO JOURNAL
    }
    */

    pub fn get_sets(&self, query: &str, _type: &RRTypes) -> Option<&RRSet> {
        self.rrmap.get(&encode_fqdn(query))?.iter().find(|s| s.get_type().eq(_type))
    }

    pub fn get_all_sets(&self, query: &str) -> Option<&Vec<RRSet>> {
        self.rrmap.get(&encode_fqdn(query))
    }

    pub fn get_all_sets_recursive(&self) -> impl Iterator<Item = (String, &Vec<RRSet>)> {
        self.rrmap.iter().map(|(key, records)| (decode_fqdn(key), records))
    }

    /*

    //METHOD 2
    pub fn get_delegation_point(&self, name: &str) -> Option<(String, &Vec<RRSet>)> {
        match self.rrmap.get_shallowest(&encode_fqdn(name)) {
            Some((name, sets)) => {
                if sets.iter().any(|set| set.get_type().eq(&RRTypes::Ns)) {
                    return Some((decode_fqdn(name), sets));
                }

                None
            }
            None => None
        }
    }

    */

    pub fn get_delegation_point(&self, query: &str) -> Option<(String, &RRSet)> {
        match self.rrmap.get_shallowest(&encode_fqdn(query)) {
            Some((name, sets)) => {
                sets
                    .iter()
                    .find(|s| s.get_type().eq(&RRTypes::Ns))
                    .map(|set| (decode_fqdn(name), set))
            }
            None => None
        }
    }

    pub fn get_journal_reader(&self) -> Result<JournalReader, JournalReaderError> {
        JournalReader::open(self.journal_path.as_ref().unwrap())
    }

    pub fn set_journal_path<P: Into<PathBuf>>(&mut self, journal_path: P) {
        self.journal_path = Some(journal_path.into());
    }

    pub fn get_journal_path(&self) -> Option<&PathBuf> {
        self.journal_path.as_ref()
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}
