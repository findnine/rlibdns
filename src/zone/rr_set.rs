use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::RRData;

#[derive(Debug, Clone)]
pub struct RRSet {
    _type: RRTypes,
    ttl: u32,
    data: Vec<u8>
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

        self.data.extend_from_slice(&data.to_bytes().unwrap());
    }

    pub fn data(&self) -> RRSetIter {
        RRSetIter {
            set: self,
            off: 0
        }
    }

    pub fn total_data(&self) -> usize {
        self.data.len()
    }
}

pub struct RRSetIter<'a> {
    set: &'a RRSet,
    off: usize
}

impl<'a> Iterator for RRSetIter<'a> {

    type Item = Box<dyn RRData>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.off >= self.set.data.len() {
            return None;
        }

        let data = <dyn RRData>::from_wire(self.set._type, &RRClasses::In, &self.set.data[self.off..], 0).unwrap();
        self.off += 2+u16::from_be_bytes([self.set.data[self.off], self.set.data[self.off+1]]) as usize;

        Some(data)
    }
}
