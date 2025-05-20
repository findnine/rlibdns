use crate::records::inter::record_base::RecordBase;

pub struct Zone {
    name: String,
    records: Vec<Box<dyn RecordBase>>
}

impl Zone {

    pub fn new(name: String) -> Self {
        Self {
            name,
            records: Vec::new()
        }
    }
}
