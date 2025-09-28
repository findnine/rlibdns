use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::rr_set::RRSet;

#[derive(Debug, Clone)]
pub struct RRName {
    fqdn: String,
    sets: Vec<RRSet>
}

impl RRName {

    pub fn new(fqdn: &str, /*class: RRClasses, _type: RRTypes*/) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            sets: Vec::new()
            //class: Default::default(),
            //_type
        }
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = fqdn.to_string();
    }

    pub fn get_fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn add_set(&mut self, set: RRSet) {
        self.sets.push(set);
    }

    pub fn get_sets(&self) -> &Vec<RRSet> {
        &self.sets
    }

    pub fn get_sets_mut(&mut self) -> &mut Vec<RRSet> {
        &mut self.sets
    }

    /*
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
    */
}
