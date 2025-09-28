use std::collections::BTreeMap;
use crate::journal::journal::Journal;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{decode_fqdn, encode_fqdn};
use crate::utils::trie::trie::Trie;
use crate::zone::inter::zone_types::ZoneTypes;

#[derive(Debug, Clone)]
pub struct Zone {
    _type: ZoneTypes,
    records: Trie<BTreeMap<RRTypes, Vec<Box<dyn RecordBase>>>>,
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
    }

    pub fn get_all_records(&self, name: &str) -> Option<&BTreeMap<RRTypes, Vec<Box<dyn RecordBase>>>> {
        self.records.get(&encode_fqdn(name))
    }

    pub fn get_all_records_recursive(&self) -> impl Iterator<Item = (String, &BTreeMap<RRTypes, Vec<Box<dyn RecordBase>>>)> {
        self.records.iter().map(|(key, records)| (decode_fqdn(key), records))
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

    pub fn set_journal(&mut self, journal: Journal) {
        self.journal = Some(journal);
    }

    pub fn get_journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    pub fn get_journal_mut(&mut self) -> Option<&mut Journal> {
        self.journal.as_mut()
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}
