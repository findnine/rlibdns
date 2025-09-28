use crate::records::inter::record_base::RecordBase;

#[derive(Debug, Clone)]
pub struct RRSet {
    ttl: u32,
    records: Vec<Box<dyn RecordBase>>
}

impl RRSet {

    pub fn new(ttl: u32) -> Self {
        Self {
            ttl,
            records: Vec::new()
        }
    }
}
