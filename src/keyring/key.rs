use crate::keyring::inter::algorithms::Algorithms;

#[derive(Debug, Clone)]
pub struct Key {
    secret: Vec<u8>,
    algorithm: Algorithms
}


