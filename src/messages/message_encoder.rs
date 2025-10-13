use std::collections::HashMap;

pub struct MessageEncoder {
    buf: Vec<u8>,
    compression_data: HashMap<Vec<u8>, u16>,
}

impl MessageEncoder {

    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(512),
            compression_data: HashMap::new()
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            compression_data: HashMap::new()
        }
    }


}
