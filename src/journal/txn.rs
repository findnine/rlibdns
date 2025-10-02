use crate::journal::inter::txn_op_codes::TxnOpCodes;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::message::MessageRecord;
use crate::records::inter::record_base::RecordBase;

#[derive(Debug, Clone)]
pub struct Txn {
    serial_0: u32,
    serial_1: u32,
    records: [Vec<MessageRecord>; 2]
}

impl Txn {

    pub fn new(serial_0: u32, serial_1: u32) -> Self {
        Self {
            serial_0,
            serial_1,
            records: Default::default()
        }
    }

    pub fn set_serial_0(&mut self, serial_0: u32) {
        self.serial_0 = serial_0;
    }

    pub fn get_serial_0(&self) -> u32 {
        self.serial_0
    }

    pub fn set_serial_1(&mut self, serial_1: u32) {
        self.serial_1 = serial_1;
    }

    pub fn get_serial_1(&self) -> u32 {
        self.serial_1
    }

    pub fn add_record(&mut self, op_code: TxnOpCodes, query: &str, class: RRClasses, ttl: u32, record: Box<dyn RecordBase>) {
        self.records[op_code as usize].push((query.to_string(), class, ttl, record));
    }

    pub fn get_records(&self, op_code: TxnOpCodes) -> impl Iterator<Item = &MessageRecord> {
        self.records[op_code as usize].iter()
    }
}
