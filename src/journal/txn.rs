use crate::journal::inter::txn_op_codes::TxnOpCodes;
use crate::records::inter::record_base::RecordBase;

#[derive(Debug, Clone)]
pub struct Txn {
    pub serial_0: u32,
    pub serial_1: u32,
    pub buckets: [Vec<(String, Box<dyn RecordBase>)>; 2]
}

impl Txn {

    pub fn new(serial_0: u32, serial_1: u32) -> Self {
        Self {
            serial_0,
            serial_1,
            buckets: Default::default()
        }
    }

    pub fn add_record(&mut self, op_code: TxnOpCodes, rec: (String, Box<dyn RecordBase>)) {
        self.buckets[op_code as usize].push(rec)
    }
}
