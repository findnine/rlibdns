use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;

#[derive(Debug, Clone)]
pub struct RRSet {
    _type: RRTypes,
    ttl: u32,
    records: Vec<Box<dyn RecordBase>>
}

impl RRSet {

    pub fn new(_type: RRTypes, ttl: u32) -> Self {
        Self {
            _type,
            ttl,
            records: Vec::new()
        }
    }

    pub fn set_type(&mut self, _type: RRTypes) {
        self._type = _type;
    }

    pub fn get_type(&self) -> RRTypes {
        self._type
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn add_record(&mut self, ttl: u32, record: Box<dyn RecordBase>) {
        if self.ttl != ttl {
            self.ttl = self.ttl.min(ttl);
        }

        self.records.push(record);
    }

    pub fn get_records(&self) -> &Vec<Box<dyn RecordBase>> {
        &self.records
    }

    pub fn total_records(&self) -> usize {
        self.records.len()
    }
}
