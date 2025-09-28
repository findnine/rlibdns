use crate::records::inter::record_base::RecordBase;

#[derive(Debug, Clone)]
pub struct RRSets {
    ttl: u32,
    records: Vec<Box<dyn RecordBase>>
}

impl RRSets {

    pub fn new(ttl: u32) -> Self {
        Self {
            ttl,
            records: Vec::new()
        }
    }
}
