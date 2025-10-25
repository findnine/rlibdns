use crate::keyring::inter::algorithms::Algorithms;
use crate::keyring::key::Key;

#[derive(Debug, Clone)]
pub struct KeyRing {

}

impl KeyRing {

    pub fn new() -> Self {
        Self {

        }
    }

    pub fn get_key(&self, fqdn: &str, algorithm: &Algorithms) -> Key {
        todo!()
    }
}
