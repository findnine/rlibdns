use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use crate::journal::journal_reader::JournalReader;
use crate::journal::txn::Txn;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{decode_fqdn, encode_fqdn};
use crate::utils::trie::trie::Trie;
use crate::zone::inter::zone_types::ZoneTypes;

#[derive(Debug, Clone)]
pub struct Zone {
    _type: ZoneTypes,
    records: Trie<BTreeMap<RRTypes, Vec<Box<dyn RecordBase>>>>,
    journal_path: Option<PathBuf>
}

impl Default for Zone {

    fn default() -> Self {
        Self {
            _type: Default::default(),
            records: Trie::new(),
            journal_path: None
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

    pub fn new_with_jnl<P: Into<PathBuf>>(_type: ZoneTypes, journal_path: P) -> Self {
        Self {
            _type,
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

    pub fn get_txns_from(&self, serial: u32) -> io::Result<Vec<Txn>> {
        let mut txns = Vec::new();
        let mut reader = JournalReader::open(self.journal_path.as_ref().unwrap())?;

        for txn in reader.iter() {
            if txn.get_serial_0() < serial {
                continue;
            }
            txns.push(txn);
        }

        Ok(txns)
    }


    pub fn set_journal<P: Into<PathBuf>>(&mut self, journal_path: P) {
        self.journal_path = Some(journal_path.into());
    }

    /*
    pub fn get_journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    pub fn get_journal_mut(&mut self) -> Option<&mut Journal> {
        self.journal.as_mut()
    }
    */

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}
