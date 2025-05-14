use std::fs::File;
use std::io;

pub struct Zone {

}

impl Zone {

    pub fn new() -> Self {
        Self {
        }
    }

    fn from_file(file_path: &str) -> io::Result<Self> {
        let mut file = File::open(file_path)?;

        //PARSE ZONE FILE


        Ok(Self {

        })
    }

    pub fn to_file(&self, path: &str) -> io::Result<()> {
        Ok(())
    }
}
