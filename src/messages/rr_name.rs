use crate::messages::rr_set::RRSet;

#[derive(Debug, Clone)]
pub struct RRName {
    fqdn: String,
    sets: Vec<RRSet>
}

impl RRName {

    pub fn new(fqdn: &str) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            sets: Vec::new()
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
}
