use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Seek, SeekFrom};
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::domain_utils::unpack_domain;

#[derive(Debug, PartialEq, Eq)]
enum ParserState {
    Init,
    Common
}

pub struct JournalParser {
    reader: BufReader<File>
}

impl JournalParser {

    pub fn open(file_path: &str) -> io::Result<Self> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader
        })
    }

    pub fn iter(&mut self) -> JournalParserIter {
        JournalParserIter {
            parser: self
        }
    }

    pub fn parse_record(&mut self) -> Option<(String, Box<dyn RecordBase>)> {
        let mut state = ParserState::Init;



        let mut buf = vec![0u8; 64];
        //self.reader.read_exact(&mut buf)?;
        self.reader.read_exact(&mut buf).unwrap();

        // Magic (first 16 bytes): ";BIND LOG V9\n" or ";BIND LOG V9.2\n"
        let magic = true;//&buf[0..16];
        let v9 = b";BIND LOG V9\n";
        let v92 = b";BIND LOG V9.2\n";
        //if !(magic.starts_with(v9) || magic.starts_with(v92)) {
        //    //return Err(io::Error::new(io::ErrorKind::InvalidData, "bad .jnl magic"));
        //}

        //let is_v92 = magic.starts_with(v92);

        // Parse header fields (big-endian u32s)
        let begin_serial = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let begin_offset = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let end_serial = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let end_offset = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let index_size = u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let source_serial = u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let flags = buf[40];

        //println!("V9 {}", is_v92);
        println!("Begin Serial {}", begin_serial);
        println!("Begin Offset {}", begin_offset);
        println!("End Serial {}", end_serial);
        println!("End Offset {}", end_offset);
        println!("Index Size {}", index_size);
        println!("Source Serial {}", source_serial);
        println!("Flags {}", flags);

        // ===== 2) OPTIONAL INDEX =====
        // Each index entry is 8 bytes: [serial(4) | offset(4)]
        self.reader.seek(SeekFrom::Current((index_size as i64) * 8)).unwrap();

        // ===== 3) POSITION TO FIRST TRANSACTION =====
        self.reader.seek(SeekFrom::Start(begin_offset as u64)).unwrap();

        while self.reader.stream_position().unwrap() < end_offset as u64 {
            let (size, rr_count, serial_0, serial_1) = match magic {
                true => {
                    buf = vec![0u8; 16];
                    self.reader.read_exact(&mut buf).unwrap();
                    let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let rr_count = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    let serial_0 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                    let serial_1 = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                    (size, Some(rr_count), serial_0, serial_1)
                }
                false => {
                    buf = vec![0u8; 12];
                    self.reader.read_exact(&mut buf).unwrap();
                    let size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let serial_0 = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    let serial_1 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                    (size, None, serial_0, serial_1)
                }
            };

            let mut remaining = size;
            let mut seen_soa = 0;

            //println!("Size {}", size);
            //println!("Serial 0 {}", serial_0);
            //println!("Serial 1 {}", serial_1);

            while remaining > 0 {
                let mut buf = vec![0u8; 4];
                self.reader.read_exact(&mut buf).unwrap();
                let rr_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                remaining -= 4 + rr_len;

                buf = vec![0u8; rr_len as usize];
                self.reader.read_exact(&mut buf).unwrap();

                let mut off = 0;

                let (query, length) = unpack_domain(&buf, off);
                off += length;


                let _type = RRTypes::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
                let record = <dyn RecordBase>::from_wire(_type, &buf, off+2).unwrap();

                if _type == RRTypes::Soa {
                    seen_soa += 1;

                    match seen_soa {
                        1 => {
                            println!("DEL");
                        }
                        2 => {
                            println!("ADD");
                        }
                        _ => unreachable!()
                    }
                }

                println!("{}: {:?}", query, record);
            }
        }

        None
    }
}

pub struct JournalParserIter<'a> {
    parser: &'a mut JournalParser
}

impl<'a> Iterator for JournalParserIter<'a> {

    type Item = (String, Box<dyn RecordBase>);

    fn next(&mut self) -> Option<Self::Item> {
        self.parser.parse_record()
    }
}
