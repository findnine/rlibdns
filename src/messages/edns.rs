use crate::rr_data::inter::opt_codes::OptCodes;
use crate::rr_data::inter::rr_data::RRDataError;

#[derive(Debug, Clone)]
pub struct Edns {
    payload_size: u16,
    ext_rcode: u8,
    version: u8,
    do_bit: bool,
    z_flags: u16,
    options: Vec<EdnsOption>
}

#[derive(Debug, Clone)]
pub struct EdnsOption {
    code: OptCodes,
    data: Vec<u8>
}

impl EdnsOption {

    pub fn new(code: OptCodes, data: &[u8]) -> Self {
        Self {
            code,
            data: data.to_vec()
        }
    }

    pub fn set_code(&mut self, code: OptCodes) {
        self.code = code;
    }

    pub fn code(&self) -> OptCodes {
        self.code
    }

    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Edns {

    pub fn new(payload_size: u16, ext_rcode: u8, version: u8, do_bit: bool, z_flags: u16, options: Vec<EdnsOption>) -> Self {
        Self {
            payload_size,
            ext_rcode,
            version,
            do_bit,
            z_flags,
            options
        }
    }

    fn from_bytes(buf: &[u8], off: usize, _len: usize) -> Result<Self, RRDataError> {
        let payload_size = u16::from_be_bytes([buf[off], buf[off+1]]);
        let ext_rcode = buf[off+2];
        let version = buf[off+3];
        //let z_flags = u16::from_be_bytes([buf[off+4], buf[off+5]]);

        let z            = u16::from_be_bytes([buf[off + 4], buf[off + 5]]);
        let do_bit       = (z & 0x8000) != 0;
        let z_flags      = z & 0x7FFF;

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        let mut off = off+8;
        let mut options = Vec::new();

        while off < data_length {
            let opt_code = OptCodes::try_from(u16::from_be_bytes([buf[off], buf[off+1]]))
                .map_err(|e| RRDataError(e.to_string()))?;
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            options.push(EdnsOption::new(opt_code, &buf[off + 4..off + 4 + length]));

            off += 4+length;
        }

        Ok(Self {
            payload_size,
            ext_rcode,
            version,
            do_bit,
            z_flags,
            options
        })
    }

    pub fn set_payload_size(&mut self, payload_size: u16) {
        self.payload_size = payload_size;
    }

    pub fn payload_size(&self) -> u16 {
        self.payload_size
    }

    pub fn set_ext_rcode(&mut self, ext_rcode: u8) {
        self.ext_rcode = ext_rcode;
    }

    pub fn ext_rcode(&self) -> u8 {
        self.ext_rcode
    }

    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn set_z_flags(&mut self, z_flags: u16) {
        self.z_flags = z_flags;
    }

    pub fn z_flags(&self) -> u16 {
        self.z_flags
    }
}
