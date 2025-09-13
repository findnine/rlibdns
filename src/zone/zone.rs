use std::io;
use crate::journal::journal_reader::JournalReader;
use crate::journal::txn::Txn;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::index_map::IndexMap;
use crate::zone::inter::zone_types::ZoneTypes;
use crate::zone::zone_reader::ZoneReader;

#[derive(Debug, Clone)]
pub struct Zone {
    _type: ZoneTypes,
    records: IndexMap<RRTypes, Vec<Box<dyn RecordBase>>>,
    children: IndexMap<String, Self>,
    journal: IndexMap<u32, Txn>
}

impl Zone {

    pub fn new(_type: ZoneTypes) -> Self {
        Self {
            _type,
            records: IndexMap::new(),
            children: IndexMap::new(),
            journal: IndexMap::new()
        }
    }

    ///Open a file at the root zone otherwise it will be a sub of this
    pub fn open(&mut self, file_path: &str, domain: &str) -> io::Result<()> {
        let mut zone = Zone::new(ZoneTypes::Master);

        let mut reader = ZoneReader::open(file_path, domain)?;
        for (name, record) in reader.iter() {
            match name.as_str() {
                "." => self.add_record(record), //BE CAREFUL WITH THIS ONE - DONT ALLOW MOST OF THE TIME
                "@" => zone.add_record(record),
                _ => zone.add_record_to(&name, record, ZoneTypes::Master)
            }
        }

        match JournalReader::open(&format!("{}.jnl", file_path)) {
            Ok(mut jnl_reader) => {
                for txn in jnl_reader.iter() {
                    zone.journal.insert(txn.get_serial_0(), txn);
                }
            }
            Err(_) => {}
        }

        self.add_zone_to(&reader.get_origin(), zone, ZoneTypes::Hint);

        Ok(())
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

    pub fn has_sub_zone(&self, name: &str) -> bool {
        self.children.contains_key(name)
    }

    pub fn add_sub_zone(&mut self, name: &str, child: Self) {
        self.children.entry(name.to_string()).or_insert(child);
    }

    pub fn add_zone_to(&mut self, name: &str, zone: Self, default_type: ZoneTypes) {
        let labels: Vec<&str> = name.split('.').rev().collect();

        if labels.is_empty() {
            return;
        }

        let mut current = self;

        for label in &labels[..labels.len() - 1] {
            current = current.children.entry(label.to_string())
                .or_insert_with(|| Self::new(default_type.clone()));
        }

        current.children.insert(labels.last().unwrap().to_string(), zone);
    }

    pub fn get_sub_zone(&self, name: &str) -> Option<&Self> {
        self.children.get(name)
    }

    pub fn get_deepest_zone(&self, name: &str) -> Option<&Self> {
        let labels: Vec<&str> = name.trim_end_matches('.').split('.').rev().collect();

        let mut current = self;
        for label in labels {
            match current.children.get(label) {
                Some(child) => current = child,
                None => return None
            }
        }

        Some(current)
    }

    pub fn get_deepest_zone_mut(&mut self, name: &str) -> Option<&mut Self> {
        let labels: Vec<&str> = name.trim_end_matches('.').split('.').rev().collect();

        let mut current = self;
        for label in labels {
            match current.children.get_mut(label) {
                Some(child) => current = child,
                None => return None,
            }
        }

        Some(current)
    }

    pub fn get_deepest_zone_with_records(&self, name: &str, _type: &RRTypes) -> Option<(String, &Self)> {
        let labels: Vec<&str> = name.trim_end_matches('.').split('.').rev().collect();

        if self.records.contains_key(_type) {
            return Some((name.to_string(), self));
        }

        let mut current = self;
        let mut last_match: Option<(String, &Self)> = None;
        let mut current_labels = Vec::new();

        for label in &labels {
            current_labels.push(*label);

            match current.children.get(*label) {
                Some(child) => {
                    current = child;
                    if let Some(records) = current.get_records(_type) {
                        if !records.is_empty() {
                            last_match = Some((current_labels.iter().rev().cloned().collect::<Vec<_>>().join("."), current));
                        }
                    }
                }
                None => {}
            }
        }

        last_match
    }

    pub fn remove_sub_zone(&mut self, name: &str) {
        self.children.remove(name);

        //UPDATE SOA
        //REMOVE FROM JOURNAL
    }

    pub fn add_record(&mut self, record: Box<dyn RecordBase>) {
        self.records.entry(record.get_type()).or_insert(Vec::new()).push(record);

        //UPDATE SOA
        //ADD TO JOURNAL
    }

    pub fn add_record_to(&mut self, name: &str, record: Box<dyn RecordBase>, default_type: ZoneTypes) {
        let labels: Vec<&str> = name.trim_end_matches('.').split('.').rev().collect();

        let mut current = self;

        for label in &labels[..labels.len().saturating_sub(1)] {
            current = current.children
                .entry(label.to_string())
                .or_insert_with(|| Self::new(default_type.clone()));
        }

        if let Some(leaf_label) = labels.last() {
            let leaf_zone = current.children
                .entry(leaf_label.to_string())
                .or_insert_with(|| Self::new(default_type.clone()));
            leaf_zone.add_record(record);
        }
    }

    pub fn get_records(&self, _type: &RRTypes) -> Option<&Vec<Box<dyn RecordBase>>> {
        self.records.get(_type)
    }

    pub fn get_all_records(&self) -> &IndexMap<RRTypes, Vec<Box<dyn RecordBase>>> {
        &self.records
    }

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

    pub fn get_txn(&self, index: u32) -> Option<&Txn> {
        self.journal.get(&index)
    }

    pub fn get_txns(&self) -> &IndexMap<u32, Txn> {
        self.journal.as_ref()
    }

    pub fn get_txns_from(&self, start: u32) -> impl Iterator<Item = (&u32, &Txn)> {
        self.journal.range(start..)
    }
}
