pub mod messages;
pub mod records;
pub mod utils;
pub mod zone;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use crate::messages::inter::names::Names;
    use crate::messages::inter::rr_types::RRTypes;
    use crate::messages::message_base::MessageBase;
    use crate::records::inter::record_base::RecordBase;
    use crate::zone::zone_parser::ZoneParser;

    type RecordMap = HashMap<String, HashMap<RRTypes, Vec<Box<dyn RecordBase>>>>;

    #[test]
    fn encode_and_decode() {
        let x = vec![ 0xa7, 0xa2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x67, 0x6f, 0x6f,
                      0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
                      0x00, 0x01, 0x00, 0x00, 0x01, 0x23, 0x00, 0x04, 0x8e, 0xfa, 0x45, 0xee, 0x00, 0x00, 0x29, 0x04,
                      0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ];

        let message = MessageBase::from_bytes(&x).unwrap();

        println!("{}", message);

        assert_eq!(x, message.to_bytes(512));
    }

    #[test]
    fn parsing() {
        let mut records = RecordMap::new();

        let mut parser = ZoneParser::new("/home/brad/Downloads/find9.net.test.zone", Names::from_str("find9.net.")).unwrap();
        for (name, record) in parser.iter() {
            println!("{}: {:?}", name, record);

            records
                .entry(name)
                .or_insert_with(HashMap::new)
                .entry(record.get_type())
                .or_insert_with(Vec::new)
                .push(record);
        }

        //println!("{:?}", records);
        println!("{:?}", records["@"][&RRTypes::A]);
    }
}
