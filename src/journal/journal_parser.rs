use std::fs::File;
use std::io;
use std::io::BufReader;
use crate::records::inter::record_base::RecordBase;

/*
- FROM WHAT I UNDERSTAND THIS IS HOW WE DECODE JNL FILES...

function open_journal(path):
    fd = open(path)
    r  = BufReader(fd)

    // ===== 1) HEADER (64 bytes) =====
    hdr = read_bytes(r, 64)

    magic = hdr[0..16]              // ASCII ";BIND LOG V9\n" or ";BIND LOG V9.2\n"
    assert magic starts_with ";BIND LOG V9"

    begin_serial = be_u32(hdr[16..20])
    begin_offset = be_u32(hdr[20..24])
    end_serial   = be_u32(hdr[24..28])
    end_offset   = be_u32(hdr[28..32])
    index_size   = be_u32(hdr[32..36])   // number of index entries
    source_serial= be_u32(hdr[36..40])
    flags        = hdr[40]               // rest is padding to 64

    // ===== 2) OPTIONAL INDEX =====
    // Each index entry is 8 bytes: [serial(4) | offset(4)]
    seek_current(r, index_size * 8)

    // ===== 3) POSITION TO FIRST TRANSACTION =====
    seek_abs(r, begin_offset)

    // ===== 4) TRANSACTION LOOP =====
    while stream_pos(r) < end_offset:
        // Transaction header:
        // older: 12 bytes  -> [ size(4) | serial0(4) | serial1(4) ]
        // newer: 16 bytes  -> [ size(4) | count(4) | serial0(4) | serial1(4) ]
        // You can decide which to read based on magic; if unsure, read 12,
        // then, if magic says V9.2, read an extra u32 as 'count'.
        size = be_u32(read_bytes(r, 4))
        if magic has "V9.2":
            rr_count = be_u32(read_bytes(r, 4))
        serial0 = be_u32(read_bytes(r, 4))
        serial1 = be_u32(read_bytes(r, 4))

        remaining = size
        seen_soa  = 0         // 0 = none, 1 = first SOA seen, 2 = second SOA seen

        // ===== 5) RECORDS IN THE TRANSACTION =====
        while remaining > 0:
            rrlen = be_u32(read_bytes(r, 4))
            rrbuf = read_bytes(r, rrlen)
            remaining -= (4 + rrlen)

            // ----- decode one RR from rrbuf -----
            (owner, typ, class, ttl, rdata) = decode_rr(rrbuf)

            if typ == SOA:
                seen_soa += 1
                if seen_soa == 1:
                    // first SOA == "pre" boundary (marks start of deletes)
                    // optionally: yield ("del", SOA) if you want to emit SOAs
                    continue
                else if seen_soa == 2:
                    // second SOA == "post" boundary (flip to adds)
                    // optionally: yield ("add", SOA)
                    continue
                // (a third SOA would be unexpected; treat as error)
            end if

            if seen_soa < 2:
                yield ("del", owner, typ, class, ttl, rdata)
            else:
                yield ("add", owner, typ, class, ttl, rdata)
        end while
    end while

    close(fd)
end function
*/

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
}

pub struct JournalParserIter<'a> {
    parser: &'a mut JournalParser
}

impl<'a> Iterator for JournalParserIter<'a> {

    type Item = (String, Box<dyn RecordBase>);

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}
