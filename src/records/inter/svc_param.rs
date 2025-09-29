use crate::records::inter::svc_param_keys::SvcParamKeys;

#[derive(Clone, Debug)]
pub struct SvcParam {
    key: SvcParamKeys,
    value: Vec<u8>
}

impl SvcParam {

    pub fn new(key: SvcParamKeys, value: Vec<u8>) -> Self {
        Self {
            key,
            value
        }
    }

    pub fn set_key(&mut self, key: SvcParamKeys) {
        self.key = key;
    }

    pub fn get_key(&self) -> &SvcParamKeys {
        &self.key
    }

    pub fn set_value(&mut self, value: Vec<u8>) {
        self.value = value;
    }

    pub fn get_value(&self) -> &Vec<u8> {
        self.value.as_ref()
    }

    pub fn get_value_mut(&mut self) -> &Vec<u8> {
        self.value.as_mut()
    }
}
