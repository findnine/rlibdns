use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::coord_utils::{encode_loc_precision, CoordUtils};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocRRData {
    version: u8,
    size: u8,
    h_precision: u8,
    v_precision: u8,
    latitude: u32,
    longitude: u32,
    altitude: u32
}

impl Default for LocRRData {

    fn default() -> Self {
        Self {
            version: 0,
            size: 0,
            h_precision: 0,
            v_precision: 0,
            latitude: 0,
            longitude: 0,
            altitude: 0
        }
    }
}

impl RRData for LocRRData {

    fn from_bytes(buf: &[u8], off: usize, _len: usize) -> Result<Self, RRDataError> {
        let version = buf[off];
        let size = buf[off+1];
        let h_precision = buf[off+2];
        let v_precision = buf[off+3];
        let latitude = u32::from_be_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);
        let longitude = u32::from_be_bytes([buf[off+8], buf[off+9], buf[off+10], buf[off+11]]);
        let altitude = u32::from_be_bytes([buf[off+12], buf[off+13], buf[off+14], buf[off+15]]);

        Ok(Self {
            version,
            size,
            h_precision,
            v_precision,
            latitude,
            longitude,
            altitude
        })
    }

    fn to_wire(&self, _compression_data: &mut HashMap<String, usize>, _off: usize) -> Result<Vec<u8>, RRDataError> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(16);

        buf.push(self.version);
        buf.push(self.size);
        buf.push(self.h_precision);
        buf.push(self.v_precision);
        buf.extend_from_slice(&self.latitude.to_be_bytes());
        buf.extend_from_slice(&self.longitude.to_be_bytes());
        buf.extend_from_slice(&self.altitude.to_be_bytes());

        Ok(buf)
    }

    fn upcast(self) -> Box<dyn RRData> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RRData> {
        Box::new(self.clone())
    }

    fn eq_box(&self, other: &dyn RRData) -> bool {
        other.as_any().downcast_ref::<Self>().map_or(false, |o| self == o)
    }
}

impl LocRRData {

    pub fn new(version: u8, size: u8, h_precision: u8, v_precision: u8, latitude: u32, longitude: u32, altitude: u32) -> Self {
        Self {
            version,
            size,
            h_precision,
            v_precision,
            latitude,
            longitude,
            altitude
        }
    }

    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn set_size(&mut self, size: u8) {
        self.size = size;
    }

    pub fn get_size(&self) -> u8 {
        self.size
    }

    pub fn set_h_precision(&mut self, h_precision: u8) {
        self.h_precision = h_precision;
    }

    pub fn get_h_precision(&self) -> u8 {
        self.h_precision
    }

    pub fn set_v_precision(&mut self, h_precision: u8) {
        self.v_precision = h_precision;
    }

    pub fn get_v_precision(&self) -> u8 {
        self.v_precision
    }
    
    pub fn set_latitude(&mut self, latitude: u32) {
        self.latitude = latitude;
    }
    
    pub fn get_latitude(&self) -> u32 {
        self.latitude
    }
    
    pub fn set_longitude(&mut self, longitude: u32) {
        self.longitude = longitude;
    }
    
    pub fn get_longitude(&self) -> u32 {
        self.longitude
    }
    
    pub fn set_altitude(&mut self, altitude: u32) {
        self.altitude = altitude;
    }
    
    pub fn get_altitude(&self) -> u32 {
        self.altitude
    }
}

impl ZoneRRData for LocRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.latitude = value.parse::<u32>()
                .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse latitude 1 param for record type LOC"))? * 3_600_000,
            1 => self.latitude = self.latitude + value.parse::<u32>()
                .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse latitude 2 param for record type LOC"))? * 60_000,
            2 => self.latitude += (value.parse::<f64>()
                .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse latitude 3 param for record type LOC"))? * 1000.0).round() as u32,
            3 => {
                let sign = match value {
                    "S" | "W" => -1,
                    "N" | "E" => 1,
                    _ => return Err(ZoneReaderError::new(ErrorKind::FormErr, "invalid direction for record type LOC"))
                };

                let val = (sign * (self.latitude as i64)) + (1 << 31);
                self.latitude = val as u32
            }
            4 => self.longitude = value.parse::<u32>()
                .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse longitude 1 param for record type LOC"))? * 3_600_000,
            5 => self.longitude = self.longitude + value.parse::<u32>()
                .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse longitude 2 param for record type LOC"))? * 60_000,
            6 => self.longitude += (value.parse::<f64>()
                .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse longitude 3 param for record type LOC"))? * 1000.0).round() as u32,
            7 => {
                let sign = match value {
                    "S" | "W" => -1,
                    "N" | "E" => 1,
                    _ => return Err(ZoneReaderError::new(ErrorKind::FormErr, "invalid direction for record type LOC"))
                };

                let val = (sign * (self.longitude as i64)) + (1 << 31);
                self.longitude = val as u32
            }
            8 => {
                let clean = value.trim_end_matches('m');
                self.altitude = (clean.parse::<f64>()
                    .map_err(|_| ZoneReaderError::new(ErrorKind::FormErr, "unable to parse altitude param for record type LOC"))? * 100.0).round() as u32;
            }
            9 => self.size = encode_loc_precision(value).map_err(|e| ZoneReaderError::new(ErrorKind::FormErr, &e.to_string()))?,
            10 => self.h_precision = encode_loc_precision(value).map_err(|e| ZoneReaderError::new(ErrorKind::FormErr, &e.to_string()))?,
            11 => self.v_precision = encode_loc_precision(value).map_err(|e| ZoneReaderError::new(ErrorKind::FormErr, &e.to_string()))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type LOC"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for LocRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (lat_deg, lat_min, lat_sec, lat_dir) = self.latitude.to_coord(true);
        let (lon_deg, lon_min, lon_sec, lon_dir) = self.longitude.to_coord(false);
        let alt = (self.altitude as f64 - 100_000.0 * 100.0) / 100.0;

        write!(f, "{} {} {:.3} {} {} {} {:.3} {} {:.2}m {:.2}m {:.2}m {:.2}m", lat_deg,
               lat_min,
               lat_sec,
               lat_dir,
               lon_deg,
               lon_min,
               lon_sec,
               lon_dir,
               alt,
               self.size as f64 / 100.0,
               self.h_precision as f64 / 100.0,
               self.v_precision as f64 / 100.0)
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x0, 0x0, 0x0, 0x6e, 0x67, 0x2d, 0xa0, 0x9c, 0xf7, 0xc5, 0x80, 0x0, 0x0, 0x0, 0x0 ];
    let record = LocRRData::from_bytes(&buf, 0, buf.len()).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}
