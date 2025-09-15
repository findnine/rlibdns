use std::collections::HashMap;

pub fn pack_fqdn(fqdn: &str, labels_map: &mut HashMap<String, usize>, off: usize, compress: bool) -> Vec<u8> {
    if fqdn.is_empty() {
        return vec![0x00];
    }

    let mut buf = Vec::new();
    let mut off = off;

    let parts: Vec<&str> = fqdn.split('.').collect();

    for i in 0..parts.len() {
        let suffix = parts[i..].join(".");

        if compress {
            if let Some(&ptr) = labels_map.get(&suffix) {
                buf.push(0xC0 | ((ptr >> 8) as u8 & 0x3F));
                buf.push((ptr & 0xFF) as u8);
                return buf;
            }
        }

        let label_bytes = parts[i].as_bytes();
        //assert!(label_bytes.len() <= 63, "label too long");
        buf.push(label_bytes.len() as u8);
        buf.extend_from_slice(label_bytes);

        if off <= 0x3FFF {
            labels_map.entry(suffix).or_insert(off);
        }
        off = off.saturating_add(label_bytes.len() + 1);
    }

    buf.push(0x00);
    buf
}

pub fn encode_fqdn(fqdn: &str) -> Vec<u8> {
    if fqdn.is_empty() {
        return vec![0x00];
    }

    let mut buf = Vec::new();

    let parts: Vec<&str> = fqdn.split('.').collect();

    for i in 0..parts.len() {
        buf.extend_from_slice(parts[i].as_bytes());
        buf.push(0x00);
    }

    buf.push(0x00);
    buf
}

pub fn unpack_fqdn(buf: &[u8], off: usize) -> (String, usize) {
    let mut builder = String::new();
    let mut pos = off;
    let mut jumped = false;
    let mut original_pos = pos;

    while pos < buf.len() {
        let length = buf[pos] as usize;
        pos += 1;

        if length == 0 {
            break;
        }

        if (length & 0xC0) == 0xC0 {
            if pos >= buf.len() {
                break;
            }
            let pointer_offset = ((length & 0x3F) << 8) | buf[pos] as usize;
            pos += 1;

            if !jumped {
                original_pos = pos;
            }
            pos = pointer_offset;
            jumped = true;

        } else {
            if !builder.is_empty() {
                builder.push('.');
            }

            if pos + length > buf.len() {
                break;
            }

            let label = &buf[pos..pos + length];
            builder.push_str(&String::from_utf8_lossy(label));
            pos += length;
        }
    }

    let final_pos = if jumped {
        original_pos

    } else {
        pos
    };

    (builder.to_lowercase(), final_pos - off)
}

fn decode_fqdn(buf: &[u8]) -> String {
    /*
    if buf == [0x00] {
        return String::new();
    }

    let mut labels: Vec<&str> = Vec::new();
    let mut start = 0;

    for i in 0..buf.len() {
        if buf[i] == 0 {
            if i > start {
                labels.push(std::str::from_utf8(&buf[start..i]).unwrap());
            }
            start = i + 1;
        }
    }
    labels.reverse();
    labels.join(".")
    */

    let mut builder = String::new();
    let mut jumped = false;
    let mut original_pos = pos;

    while pos < buf.len() {
        let length = buf[pos] as usize;
        pos += 1;

        if length == 0 {
            break;
        }

        if (length & 0xC0) == 0xC0 {
            if pos >= buf.len() {
                break;
            }
            let pointer_offset = ((length & 0x3F) << 8) | buf[pos] as usize;
            pos += 1;

            if !jumped {
                original_pos = pos;
            }
            pos = pointer_offset;
            jumped = true;

        } else {
            if !builder.is_empty() {
                builder.push('.');
            }

            if pos + length > buf.len() {
                break;
            }

            let label = &buf[pos..pos + length];
            builder.push_str(&String::from_utf8_lossy(label));
            pos += length;
        }
    }

    builder.to_lowercase()
}

pub fn fqdn_to_relative(apex: &str, child: &str) -> Option<String> {
    if apex == child {
        return Some(String::new());
    }

    if let Some(stripped) = child.strip_suffix(apex) {
        let rel = stripped.trim_end_matches('.');
        return Some(rel.to_string());
    }

    None
}
