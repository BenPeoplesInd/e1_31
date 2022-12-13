#![feature(cstr_from_bytes_until_nul)]

use std::io::Cursor;
use std::io::Write;
use std::io::Read;
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};
use std::ffi::CStr;

const HEADER: [u8; 12] = [0x41, 0x53, 0x43, 0x2d, 0x45, 0x31, 0x2e, 0x31, 0x37, 0x00, 0x00, 0x00];

pub struct e1_31_pkt {
    pub cid : [u8; 16],
    pub source_name : String,
    pub priority : u8,
    pub sync_addr : u16,
    pub seq : u8,
    pub options : u8,
    pub universe : u16,
    pub property_value_count : u16,
    pub values : Vec<u8>
}

impl e1_31_pkt {
    pub fn new() -> e1_31_pkt {
        e1_31_pkt { 
            cid: [0; 16], 
            source_name: "".to_string(), 
            priority: 100, 
            sync_addr: 0, 
            seq : 0,
            options: 0, 
            universe: 0, 
            property_value_count: 0, 
            values: Vec::new() }
    }

    pub fn deserialize(data : Vec<u8>) -> Option<e1_31_pkt> {
        let mut rv = e1_31_pkt::new();
        let mut cursor = Cursor::new(data);

        let mut pad_bytes : [u8; 4] = [0; 4];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        // Read the header
        let mut pad_bytes : [u8; 12] = [0; 12];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        if !pad_bytes.starts_with(&HEADER) {
            return None;
        }

        let mut pad_bytes : [u8; 6] = [0; 6];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        // Read the CID
        if let Err(_) = cursor.read_exact(&mut rv.cid) {
            return None;
        }

        let mut pad_bytes : [u8; 6] = [0; 6];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        let mut source_name_bytes : [u8; 64] = [0; 64];

        if let Err(_) = cursor.read_exact(&mut source_name_bytes) {
            return None;
        }

        rv.source_name = String::from_utf8_lossy(CStr::from_bytes_until_nul(&source_name_bytes).unwrap().to_bytes()).to_string();

        rv.priority = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };

        rv.sync_addr = match cursor.read_u16::<BigEndian>() {
            Ok(n) => n,
            Err(_) => return None,
        };

        rv.seq = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };

        rv.options = match cursor.read_u8() {
            Ok(n) => n,
            Err(_) => return None,
        };        

        rv.universe = match cursor.read_u16::<BigEndian>() {
            Ok(n) => n,
            Err(_) => return None,
        };
    
        let mut pad_bytes : [u8; 8] = [0; 8];
        if let Err(_) = cursor.read_exact(&mut pad_bytes) {
            return None;
        }

        rv.property_value_count = match cursor.read_u16::<BigEndian>() {
            Ok(n) => n,
            Err(_) => return None,
        };

        for _ in 0..rv.property_value_count {
            let v : u8 = match cursor.read_u8() {
                Ok(n) => n,
                Err(_) => return None,
            };        
            rv.values.push(v);
        }

        return Some(rv);
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = Cursor::new(&mut data);

        cursor.write_u16::<BigEndian>(0x0010).unwrap();
        cursor.write_u16::<BigEndian>(0x0000).unwrap();
        cursor.write_all(&HEADER).unwrap();
        cursor.write_u16::<BigEndian>((0x07_u16 << 24) + self.property_value_count + 109).unwrap();
        cursor.write_u32::<BigEndian>(0x04).unwrap();

        cursor.write_all(&self.cid).unwrap();
        cursor.write_u16::<BigEndian>((0x07_u16 << 24) + self.property_value_count + 87).unwrap();

        cursor.write_u32::<BigEndian>(0x02);

        let source_bytes = self.source_name.as_bytes();

        let mut source_array : [u8; 64] = [0; 64];

        let mut index = 0;

        for c in source_bytes {
            source_array[index] = *c;
            index += 1;
            if index > 64 {
                break;
            }
        }

        cursor.write_all(&source_array).unwrap();

        cursor.write_u8(self.priority).unwrap();

        cursor.write_u16::<BigEndian>(self.sync_addr).unwrap();

        cursor.write_u8(self.seq).unwrap();

        cursor.write_u8(self.options).unwrap();

        cursor.write_u16::<BigEndian>(self.universe).unwrap();

        cursor.write_u16::<BigEndian>((0x07_u16 << 24) + self.property_value_count + 10).unwrap();

        cursor.write_u8(0x02).unwrap();
        cursor.write_u8(0xa1).unwrap();
        cursor.write_u16::<BigEndian>(0x00).unwrap();
        cursor.write_u16::<BigEndian>(0x01).unwrap();
        cursor.write_u16::<BigEndian>(self.property_value_count).unwrap();
        
        for s in &self.values {
            cursor.write_u8(*s).unwrap();
        }

        return data;
    }

}