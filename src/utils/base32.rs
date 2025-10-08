use std::io;

/// RFC 4648 Base32 alphabet (standard): A-Z 2-7
const B32_STD: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode(input: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;

    while i + 5 <= input.len() {
        let b1 = input[i];
        let b2 = input[i + 1];
        let b3 = input[i + 2];
        let b4 = input[i + 3];
        let b5 = input[i + 4];

        out.push(B32_STD[(b1 >> 3) as usize] as char);
        out.push(B32_STD[((b1 & 0x07) << 2 | (b2 >> 6)) as usize] as char);
        out.push(B32_STD[((b2 >> 1) & 0x1F) as usize] as char);
        out.push(B32_STD[((b2 & 0x01) << 4 | (b3 >> 4)) as usize] as char);
        out.push(B32_STD[((b3 & 0x0F) << 1 | (b4 >> 7)) as usize] as char);
        out.push(B32_STD[((b4 >> 2) & 0x1F) as usize] as char);
        out.push(B32_STD[((b4 & 0x03) << 3 | (b5 >> 5)) as usize] as char);
        out.push(B32_STD[(b5 & 0x1F) as usize] as char);

        i += 5;
    }

    let rem = input.len() - i;
    if rem > 0 {
        let mut pad_chars = 0usize;
        let b1 = input[i];
        let b2 = if rem >= 2 { input[i + 1] } else { 0 };
        let b3 = if rem >= 3 { input[i + 2] } else { 0 };
        let b4 = if rem >= 4 { input[i + 3] } else { 0 };

        match rem {
            1 => {
                out.push(B32_STD[(b1 >> 3) as usize] as char);
                out.push(B32_STD[((b1 & 0x07) << 2) as usize] as char);
                pad_chars = 6;
            }
            2 => {
                out.push(B32_STD[(b1 >> 3) as usize] as char);
                out.push(B32_STD[((b1 & 0x07) << 2 | (b2 >> 6)) as usize] as char);
                out.push(B32_STD[((b2 >> 1) & 0x1F) as usize] as char);
                out.push(B32_STD[((b2 & 0x01) << 4) as usize] as char);
                pad_chars = 4;
            }
            3 => {
                out.push(B32_STD[(b1 >> 3) as usize] as char);
                out.push(B32_STD[((b1 & 0x07) << 2 | (b2 >> 6)) as usize] as char);
                out.push(B32_STD[((b2 >> 1) & 0x1F) as usize] as char);
                out.push(B32_STD[((b2 & 0x01) << 4 | (b3 >> 4)) as usize] as char);
                out.push(B32_STD[((b3 & 0x0F) << 1) as usize] as char);
                pad_chars = 3;
            }
            4 => {
                out.push(B32_STD[(b1 >> 3) as usize] as char);
                out.push(B32_STD[((b1 & 0x07) << 2 | (b2 >> 6)) as usize] as char);
                out.push(B32_STD[((b2 >> 1) & 0x1F) as usize] as char);
                out.push(B32_STD[((b2 & 0x01) << 4 | (b3 >> 4)) as usize] as char);
                out.push(B32_STD[((b3 & 0x0F) << 1 | (b4 >> 7)) as usize] as char);
                out.push(B32_STD[((b4 >> 2) & 0x1F) as usize] as char);
                out.push(B32_STD[((b4 & 0x03) << 3) as usize] as char);
                pad_chars = 1;
            }
            _ => unreachable!(),
        }
        for _ in 0..pad_chars {
            out.push('=');
        }
    }

    out
}

pub fn decode(input: &str) -> io::Result<Vec<u8>> {
    // Build decode map for A-Z2-7 and '='
    let mut map = [255u8; 256];
    for (i, &c) in B32_STD.iter().enumerate() {
        map[c as usize] = i as u8;
        // accept lowercase too
        if c.is_ascii_uppercase() {
            map[(c as char).to_ascii_lowercase() as usize] = i as u8;
        }
    }
    map[b'=' as usize] = 0;

    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut out = Vec::new();

    for &ch in input.as_bytes().iter().filter(|&&b| b != b'\r' && b != b'\n' && b != b' ' && b != b'\t') {
        if ch == b'=' { break; } // padding ends stream
        let v = map.get(ch as usize).copied().unwrap_or(255);
        if v == 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid base32 symbol"));
        }
        acc = (acc << 5) | (v as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}
