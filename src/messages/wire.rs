use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::ops::RangeBounds;
use std::ops::Bound::*;

pub trait FromWire {

    fn from_wire(context: &mut FromWireContext) -> Result<Self, WireError> where Self: Sized;
}

pub trait FromWireLen {

    fn from_wire(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> where Self: Sized;
}

pub trait ToWire {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WireError {
    Truncated(String),
    Format(String),
    Other(String)
}

impl fmt::Display for WireError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Truncated(v) => v,
            Self::Format(v) => v,
            Self::Other(v) => v
        })
    }
}

pub struct ToWireContext {
    buf: Vec<u8>,
    capacity: usize,
    compression_map: HashMap<Vec<u8>, u16>,
    is_compression: bool
}

impl ToWireContext {

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            capacity,
            compression_map: HashMap::new(),
            is_compression: true
        }
    }

    pub fn pos(&self) -> usize {
        self.buf.len()
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), WireError> {
        self.buf.extend_from_slice(buf);
        Ok(())
    }

    pub fn skip(&mut self, n: usize) -> Result<(), WireError> {
        if self.buf.len()+n > self.capacity {
            return Err(WireError::Truncated(self.buf.len().to_string()));
        }
        Ok(unsafe { self.buf.set_len(self.buf.len()+n); })
    }

    pub fn patch<R: RangeBounds<usize>>(&mut self, range: R, buf: &[u8]) -> Result<(), WireError> {
        let start = match range.start_bound() {
            Included(&x) => x,
            Excluded(&x) => x + 1,
            Unbounded => 0,
        };
        let end = match range.end_bound() {
            Included(&x) => x + 1,
            Excluded(&x) => x,
            Unbounded => self.buf.len(),
        };

        if end > self.buf.len() || start > end || buf.len() != (end - start) {
            return Err(WireError::Format("invalid patch range".into()));
        }

        self.buf[start..end].copy_from_slice(buf);
        Ok(())
    }

    pub fn write_name(&mut self, fqdn: &str) -> Result<(), WireError> {
        if fqdn == "." {
            0u8.to_wire(self)?;
            return Ok(());
        }

        let labels: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
        if self.is_compression {
            // try longest-known suffix
            for i in 0..labels.len() {
                let suffix = labels[i..].join(".").into_bytes();
                if let Some(&off) = self.compression_map.get(&suffix) {
                    // write prefix labels raw
                    for l in &labels[..i] {
                        let start = self.pos();
                        (l.len() as u8).to_wire(self)?;
                        self.buf.extend_from_slice(l.as_bytes());
                        let remain = labels[i..].join(".").into_bytes();
                        self.compression_map.entry(remain).or_insert(start as u16);
                    }
                    let ptr = 0xC000u16 | off;
                    ptr.to_wire(self)?;
                    return Ok(());
                }
            }
        }
        for i in 0..labels.len() {
            let l = labels[i];
            let start = self.pos();
            (l.len() as u8).to_wire(self)?;
            self.buf.extend_from_slice(l.as_bytes());
            if self.is_compression {
                let suffix = labels[i..].join(".").into_bytes();
                self.compression_map.entry(suffix).or_insert(start as u16);
            }
        }

        0u8.to_wire(self)?;
        Ok(())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

pub struct FromWireContext<'a> {
    buf: &'a [u8],
    pos: usize
}

impl<'a> FromWireContext<'a> {

    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Format("overflow".to_string()))?;
        if end > self.buf.len() {
            return Err(WireError::Truncated("read".to_string()));
        }

        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn peek(&self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Format("overflow".into()))?;
        if end > self.buf.len() {
            return Err(WireError::Truncated("peek".into()));
        }

        Ok(&self.buf[self.pos..end])
    }

    pub fn name(&mut self) -> Result<String, WireError> {
        let mut out = String::new();
        let mut off = self.pos;
        let mut jumped = false;
        let mut steps = 0usize;

        loop {
            if steps > 255 { return Err(WireError::Format("too many labels".to_string())); }
            if off >= self.buf.len() { return Err(WireError::Truncated("name".to_string())); }
            let len = self.buf[off];
            if len == 0 {
                if !jumped {
                    self.pos = off + 1;
                }
                if out.is_empty() {
                    out.push('.');
                } else if !out.ends_with('.') {
                    out.push('.');
                }
                return Ok(out);
            }
            if (len & 0xC0) == 0xC0 {
                if off + 1 >= self.buf.len() { return Err(WireError::Truncated("name ptr".to_string())); }
                let ptr = (((len as u16 & 0x3F) << 8) | self.buf[off + 1] as u16) as usize;
                if !jumped { self.pos = off + 2; }
                off = ptr;
                jumped = true;
            } else {
                let l = len as usize;
                if off + 1 + l > self.buf.len() { return Err(WireError::Truncated("label".to_string())); }
                let lab = &self.buf[off + 1 .. off + 1 + l];
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&String::from_utf8_lossy(lab).to_ascii_lowercase());
                off += 1 + l;
            }
            steps += 1;
        }
    }
}

impl FromWire for u8 {

    fn from_wire(context: &mut FromWireContext) -> Result<Self, WireError> {
        Ok(context.take(1)?[0])
    }
}

impl ToWire for u8 {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        Ok(context.buf.push(*self))
    }
}

impl FromWire for u16 {

    fn from_wire(context: &mut FromWireContext) -> Result<Self, WireError> {
        let b = context.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

impl ToWire for u16 {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        Ok(context.buf.extend_from_slice(&self.to_be_bytes()))
    }
}

impl FromWire for u32 {

    fn from_wire(context: &mut FromWireContext) -> Result<Self, WireError> {
        let b = context.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

impl ToWire for u32 {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        Ok(context.buf.extend_from_slice(&self.to_be_bytes()))
    }
}
