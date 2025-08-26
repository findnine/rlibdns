use std::collections::HashMap;

pub fn pack_domain(domain: &str, labels_map: &mut HashMap<String, usize>, off: usize, compress: bool) -> Vec<u8> {
    /*
    if domain.is_empty() {
        return vec![0x00];
    }

    let mut buf = Vec::new();
    let mut off = off;

    let parts: Vec<&str> = domain.split('.').collect();

    for i in 0..parts.len() {
        let label = parts[i..].join(".");

        if compress {
            if let Some(&off) = labels_map.get(&label) {
                buf.extend_from_slice(&[(0xC0 | ((off >> 8) & 0x3F)) as u8, (off & 0xFF) as u8]);
                return buf;
            }
        }

        let label_bytes = parts[i].as_bytes();
        buf.push(label_bytes.len() as u8);
        buf.extend_from_slice(label_bytes);
        labels_map.insert(label, off);
        off += label_bytes.len() + 1;
    }

    buf.push(0x00);

    buf
    */


    let d = domain.trim_end_matches('.');
    if d.is_empty() { return vec![0]; }

    let parts: Vec<&str> = d.split('.').collect();
    let mut buf = Vec::new();
    let mut off = off;

    for i in 0..parts.len() {
        let suffix = parts[i..].join(".").to_ascii_lowercase();

        if compress {
            if let Some(&ptr) = labels_map.get(&suffix) {
                buf.push(0xC0 | ((ptr >> 8) as u8 & 0x3F));
                buf.push((ptr & 0xFF) as u8);
                return buf;
            }
        }

        let lbl = parts[i].as_bytes();
        assert!(lbl.len() <= 63, "label too long");
        buf.push(lbl.len() as u8);
        buf.extend_from_slice(lbl);

        if off <= 0x3FFF {
            labels_map.entry(suffix).or_insert(off);
        }
        off = off.saturating_add((lbl.len() as u16 + 1) as usize);
    }

    buf.push(0);
    buf
}

pub fn unpack_domain(buf: &[u8], off: usize) -> (String, usize) {
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

    let final_pos = if jumped { original_pos } else { pos };
    (builder.to_lowercase(), final_pos - off)
}
