use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::RRData;

#[derive(Debug, Clone)]
pub struct Record {
    fqdn: String,
    class: RRClasses,
    _type: RRTypes,
    ttl: u32,
    data: Option<Box<dyn RRData>>
}

impl Record {

    pub fn new(fqdn: &str, class: RRClasses, _type: RRTypes, ttl: u32, data: Option<Box<dyn RRData>>) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            class,
            _type,
            ttl,
            data
        }
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = fqdn.to_string();
    }

    pub fn get_fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn set_type(&mut self, _type: RRTypes) {
        self._type = _type;
    }

    pub fn get_type(&self) -> RRTypes {
        self._type
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_data(&mut self, data: Option<Box<dyn RRData>>) {
        self.data = data;
    }

    pub fn get_data(&self) -> Option<&Box<dyn RRData>> {
        self.data.as_ref()
    }
}
