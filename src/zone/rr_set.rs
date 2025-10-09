use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::RRData;

#[derive(Debug, Clone)]
pub struct RRSet {
    _type: RRTypes,
    ttl: u32,
    data: Vec<Box<dyn RRData>>
}

impl RRSet {

    pub fn new(_type: RRTypes, ttl: u32) -> Self {
        Self {
            _type,
            ttl,
            data: Vec::new()
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

    pub fn add_data(&mut self, ttl: u32, data: Box<dyn RRData>) {
        if self.ttl != ttl {
            self.ttl = self.ttl.min(ttl);
        }

        self.data.push(data);
    }

    pub fn get_data(&self) -> &Vec<Box<dyn RRData>> {
        &self.data
    }

    pub fn total_data(&self) -> usize {
        self.data.len()
    }
}
