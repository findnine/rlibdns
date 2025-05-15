use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};
use crate::records::inter::record_base::RecordBase;

pub struct Zone {
    records: Vec<Box<dyn RecordBase>>
}

impl Zone {

    pub fn new() -> Self {
        Self {
            records: Vec::new()
        }
    }

    pub fn from_file(file_path: &str) -> io::Result<Self> {
        let file = File::open(file_path)?;

        //PARSE ZONE FILE
        let reader = BufReader::new(file);

        let mut records = Vec::new();


        let default_origin = "find9.net";

        let mut origin = default_origin.trim_end_matches('.').to_string();
        let mut default_ttl: Option<u32> = None;

        let mut multiline = String::new();



        for line in reader.lines() {
            let line = line?;
            let mut line = line.split(';').next().unwrap_or("").trim().to_string();

            if line.is_empty() {
                continue;
            }

            if !multiline.is_empty() {
                multiline.push(' ');
                multiline.push_str(&line);

                if !line.contains(')') {
                    continue;
                }

                line = multiline.trim().to_string();
                multiline.clear();

            } else if line.contains('(') && !line.contains(')') {
                multiline = line.to_string();
                continue;
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            
            if line.starts_with('$') {
                match tokens[0] {
                    "$ORIGIN" if tokens.len() > 1 => {
                        origin = tokens[1].trim_end_matches('.').to_string();
                    }
                    "$TTL" if tokens.len() > 1 => {
                        default_ttl = tokens[1].parse().ok();
                    }
                    _ => {}
                }
                continue;
            }

            if tokens.len() < 3 {
                continue;
            }

            println!("{:?}", tokens);

            /*
            if continued {
                multiline.push(' ');
                multiline.push_str(line);

                if line.contains(')') {
                    continued = false;
                } else {
                    continue;
                }

            } else if line.contains('(') && !line.contains(')') {
                multiline = line.to_string();
                continued = true;
                continue;

            } else {
                multiline = line.to_string();
            }

            let line = multiline.trim();
            if line.starts_with('$') {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                match tokens[0] {
                    "$ORIGIN" if tokens.len() > 1 => {
                        origin = tokens[1].trim_end_matches('.').to_string();
                    }
                    "$TTL" if tokens.len() > 1 => {
                        default_ttl = tokens[1].parse().ok();
                    }
                    _ => {}
                }
                continue;
            }

            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 3 {
                continue;
            }

            let mut name = "";
            let mut ttl: Option<u32> = None;
            let mut class = "IN";
            let mut rtype = "";
            let mut rdata_start = 0;

            let type_index = tokens.iter().position(|t| !t.parse::<u32>().is_ok()).unwrap();

            match type_index {
                0 => {}
                1 => name = tokens[0],
                2 => {
                    name = tokens[0];
                    if let Ok(parsed_ttl) = tokens[1].parse() {
                        ttl = Some(parsed_ttl);
                    } else {
                        class = tokens[1];
                    }
                }
                3 => {
                    name = tokens[0];
                    ttl = tokens[1].parse().ok();
                    class = tokens[2];
                }
                _ => continue
            }

            rtype = tokens[type_index];
            rdata_start = type_index + 1;

            let rdata = tokens[rdata_start..].join(" ");

            let fqdn = if name.is_empty() {
                origin.clone()
            } else if name == "@" {
                origin.clone()
            } else if name.ends_with('.') {
                name.trim_end_matches('.').to_string()
            } else {
                format!("{}.{}", name, origin)
            };

            println!("name: {}  ttl: {:?}  class: {}  rtpe: {}  rdata: {}", fqdn, ttl, class.to_string(), rtype, rdata);
            */
        }




        Ok(Self {
            records
        })
    }

    pub fn to_file(&self, path: &str) -> io::Result<()> {
        Ok(())
    }

    pub fn get_records(&self) -> Vec<Box<dyn RecordBase>> {
        todo!()
    }
}
