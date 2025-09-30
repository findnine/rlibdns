use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::{RecordBase, RecordError};
use crate::utils::coord_utils::CoordUtils;

#[derive(Clone, Debug)]
pub struct LocRecord {
    pub(crate) version: u8,
    pub(crate) size: u8,
    pub(crate) h_precision: u8,
    pub(crate) v_precision: u8,
    pub(crate) latitude: u32,
    pub(crate) longitude: u32,
    pub(crate) altitude: u32
}

impl Default for LocRecord {

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

impl RecordBase for LocRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Result<Self, RecordError> {
        //let z = u16::from_be_bytes([buf[off], buf[off+1]]);

        let version = buf[off+2];
        let size = buf[off+3];
        let h_precision = buf[off+4];
        let v_precision = buf[off+5];
        let latitude = u32::from_be_bytes([buf[off+6], buf[off+7], buf[off+8], buf[off+9]]);
        let longitude = u32::from_be_bytes([buf[off+10], buf[off+11], buf[off+12], buf[off+13]]);
        let altitude = u32::from_be_bytes([buf[off+14], buf[off+15], buf[off+16], buf[off+17]]);

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

    fn to_bytes(&self, _labels: &mut Vec<(String, usize)>, _off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 18];

        buf[3] = self.version;
        buf[4] = self.size;
        buf[5] = self.h_precision;
        buf[6] = self.v_precision;
        buf.splice(6..10, self.latitude.to_be_bytes());
        buf.splice(10..14, self.longitude.to_be_bytes());
        buf.splice(14..18, self.altitude.to_be_bytes());

        buf.splice(0..2, ((buf.len()-2) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Loc
    }

    fn upcast(self) -> Box<dyn RecordBase> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }
}

impl LocRecord {

    pub fn new() -> Self {
        Self {
            ..Self::default()
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

impl fmt::Display for LocRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (lat_deg, lat_min, lat_sec, lat_dir) = self.latitude.to_coord(true);
        let (lon_deg, lon_min, lon_sec, lon_dir) = self.longitude.to_coord(false);
        let alt = (self.altitude as f64 - 100_000.0 * 100.0) / 100.0;

        write!(f, "{:<8}{} {} {:.3} {} {} {} {:.3} {} {:.2}m {:.2}m {:.2}m {:.2}m", self.get_type().to_string(),
               lat_deg,
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
    let buf = vec![ 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x6e, 0x67, 0x2d, 0xa0, 0x9c, 0xf7, 0xc5, 0x80, 0x0, 0x0, 0x0, 0x0 ];
    let record = LocRecord::from_bytes(&buf, 0).unwrap();
    assert_eq!(buf, record.to_bytes(&mut Vec::new(), 0).unwrap());
}
