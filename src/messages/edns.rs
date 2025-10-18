
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
    code: u16,
    data: Vec<u8>
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
