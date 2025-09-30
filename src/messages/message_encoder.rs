
#[derive(Clone, Debug)]
pub struct MessageEncoder {
    buf: Vec<u8>,
    labels: Vec<(String, usize)>
}

impl MessageEncoder {

    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            labels: Vec::new()
        }
    }

    pub fn write(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn write_u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    //MAY NEED EDITS...
    pub fn write_fqdn(&mut self, fqdn: &str, compress: bool) {
        if fqdn.is_empty() {
            self.buf.push(0x00);
        }

        let mut buf = Vec::new();
        let mut position = self.buf.len();

        let parts: Vec<&str> = fqdn.split('.').collect();

        for i in 0..parts.len() {
            let suffix = parts[i..].join(".");

            if compress {
                if let Some((_, ptr)) = self.labels.iter().find(|(s, _)| s.eq(&suffix)) {
                    self.buf.push(0xC0 | ((ptr >> 8) as u8 & 0x3F));
                    self.buf.push((ptr & 0xFF) as u8);
                    return;
                }
            }

            let label_bytes = parts[i].as_bytes();
            //assert!(label_bytes.len() <= 63, "label too long");
            buf.push(label_bytes.len() as u8);
            buf.extend_from_slice(label_bytes);

            if position <= 0x3FFF {
                if !self.labels.iter().any(|(k, _)| k.eq(&suffix)) {
                    self.labels.push((suffix.to_string(), position));
                }
            }

            position = position.saturating_add(label_bytes.len() + 1);
        }

        buf.push(0x00);
    }
}
