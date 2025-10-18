
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
}
