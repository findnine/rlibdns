use std::collections::{BTreeMap, BTreeSet};
use std::io;
use crate::journal::journal::Journal;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{decode_fqdn, encode_fqdn};
use crate::utils::index_map::IndexMap;
use crate::utils::trie::trie::Trie;
use crate::zone::inter::zone_types::ZoneTypes;
use crate::zone::zone_reader::ZoneReader;

#[derive(Debug, Clone)]
pub struct Zone {
    _type: ZoneTypes,
    records: Trie<BTreeMap<RRTypes, Vec<Box<dyn RecordBase>>>>,
    //records: IndexMap<String, IndexMap<RRTypes, Vec<Box<dyn RecordBase>>>>,
    journal: Option<Journal>
}

impl Default for Zone {

    fn default() -> Self {
        Self {
            _type: Default::default(),
            records: Trie::new(),
            journal: None
        }
    }
}

impl Zone {

    pub fn new(_type: ZoneTypes) -> Self {
        Self {
            _type,
            ..Default::default()
        }
    }

    pub fn set_type(&mut self, _type: ZoneTypes) {
        self._type = _type;
    }

    pub fn get_type(&self) -> ZoneTypes {
        self._type
    }

    pub fn is_authority(&self) -> bool {
        self._type.eq(&ZoneTypes::Master) || self._type.eq(&ZoneTypes::Slave)
    }

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

    pub fn get_records(&self, name: &str, _type: &RRTypes) -> Option<&Vec<Box<dyn RecordBase>>> {
        self.records.get(&encode_fqdn(name))?.get(_type)
        //self.records.get(name)?.get(_type)
    }

    pub fn get_all_records(&self, name: &str) -> Option<&BTreeMap<RRTypes, Vec<Box<dyn RecordBase>>>> {
        self.records.get(&encode_fqdn(name))
        //self.records.get(name)
    }

    pub fn get_delegation_point(&self, name: &str) -> Option<(String, &BTreeMap<RRTypes, Vec<Box<dyn RecordBase>>>)> {
        match self.records.get_shallowest(&encode_fqdn(name)) {
            Some((name, rrmap)) => {
                if rrmap.contains_key(&RRTypes::Ns) {
                    return Some((decode_fqdn(name), rrmap));
                }

                None
            }
            None => None
        }
    }

    /*
    pub fn get_all_records_recursive(&self) -> IndexMap<String, Vec<&Box<dyn RecordBase>>> {
        let mut res = IndexMap::new();
        self.collect_records(String::new(), &mut res);
        res
    }

    fn collect_records<'a>(&'a self, fqdn: String, map: &mut IndexMap<String, Vec<&'a Box<dyn RecordBase>>>) {
        let recs: Vec<&Box<dyn RecordBase>> = self
            .records
            .iter()
            .filter(|(ty, _)| **ty != RRTypes::Soa)
            .flat_map(|(_, v)| v.iter())
            .collect();

        if !recs.is_empty() {
            map.insert(fqdn.to_string(), recs);
        }

        for (label, child) in &self.children {
            let is_delegated = child.records.get(&RRTypes::Soa).map_or(false, |recs| !recs.is_empty());

            if is_delegated {
                continue;
            }

            child.collect_records(format!("{}.{}", label, fqdn), map);
        }
    }
    */

    /*
    pub fn set_journal(&mut self, journal: Journal) {
        self.journal = Some(journal);
    }

    pub fn set_journal_for(&mut self, name: &str, journal: Journal) -> io::Result<()> {
        let labels: Vec<&str> = name.trim_end_matches('.').split('.').rev().collect();

        let mut current = self;

        for label in labels {
            current = current.children.get_mut(label).ok_or(io::ErrorKind::NotFound)?;
        }

        current.journal = Some(journal);

        Ok(())
    }

    pub fn get_journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    pub fn get_journal_mut(&mut self) -> Option<&mut Journal> {
        self.journal.as_mut()
    }*/

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}
