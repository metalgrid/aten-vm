//! Captured SID-token plug-in/auth profile; see inspection/vusb-auth.md.
use crate::Result;

const KEY: &[u8] = b"BX80570E3110Q814A447";

pub fn rc4(data: &mut [u8], key: &[u8]) {
    assert!(!key.is_empty());
    let mut s = std::array::from_fn::<_, 256, _>(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for b in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        *b ^= s[s[i as usize].wrapping_add(s[j as usize]) as usize];
    }
}

pub fn descriptors() -> Vec<u8> {
    let mut result = Vec::new();
    for r in descriptor_records(0x0ea0, 0x1111) {
        result.push(r.len() as u8);
        result.extend(r);
    }
    result
}

/// The Insyde HTML5 client (novnc/include/vstorage.js) ships the same record
/// set and strings; JASWInit only patches the device descriptor identity to
/// VID 0x0b1f / PID 0x03ea. GetDevCMDSet rewrites the interface subclass to 6
/// for ISO media and single-ISO mounts enable interface group 0 only, so the
/// assembled configuration record stays byte-identical to the capture's.
pub fn descriptors_html5() -> Vec<u8> {
    let mut result = Vec::new();
    for r in descriptor_records(0x0b1f, 0x03ea) {
        result.push(r.len() as u8);
        result.extend(r);
    }
    result
}

fn descriptor_records(vid: u16, pid: u16) -> Vec<Vec<u8>> {
    vec![
        vec![
            0x12,
            1,
            0,
            2,
            0,
            0,
            0,
            0x40,
            (vid & 0xff) as u8,
            (vid >> 8) as u8,
            (pid & 0xff) as u8,
            (pid >> 8) as u8,
            0,
            2,
            0,
            0,
            0,
            1,
        ],
        vec![
            9, 2, 0x27, 0, 1, 1, 0, 0x80, 0x64, 9, 4, 0, 0, 3, 8, 6, 0x50, 0, 7, 5, 1, 2, 0, 2,
            0xff, 7, 5, 0x82, 2, 0, 2, 0xff, 7, 5, 0x83, 3, 2, 0, 1,
        ],
        vec![4, 3, 9, 4],
        usb_string("Flash Disk      "),
        usb_string("4E8F092C3FD7F8F7"),
        usb_string("SN000PQI009 "),
        vec![0],
        vec![0x0a, 6, 0, 2, 0, 0, 0, 0x40, 1, 0],
    ]
}

fn usb_string(s: &str) -> Vec<u8> {
    let mut result = vec![(2 + s.encode_utf16().count() * 2) as u8, 3];
    for c in s.encode_utf16() {
        result.extend(c.to_le_bytes());
    }
    result
}

pub fn validate_tokens(user: &str, pass: &str) -> Result<()> {
    for (name, value, width) in [("user token", user, 16), ("password token", pass, 20)] {
        if value.is_empty() || !value.is_ascii() || value.len() > width || value.contains('\0') {
            return Err(
                format!("{name} must be nonempty NUL-free ASCII, at most {width} bytes").into(),
            );
        }
    }
    Ok(())
}

pub fn build(user: &str, pass: &str, nonce: [u8; 4], slot: u8) -> Result<Vec<u8>> {
    validate_tokens(user, pass)?;
    if slot > 2 {
        return Err("slot must be in 0..=2".into());
    }
    let mut body = plug_in_body(user, pass, nonce, slot);
    body.extend(descriptors());
    rc4(&mut body, KEY);
    let mut packet = vec![0, 0x80, 0, 1, 44, 0, 0, 0];
    packet.extend(body);
    Ok(packet)
}

/// The HTML5 client sends the same plug-in packet structure unencrypted
/// (MtMethod_Media2 rejects the ENCRYPT_RC4 bit, PlugInPkt_Encrypt_en=0), with
/// JASWInit's control byte: totalDevNumber | SID auth | HTML5 flag | slot<<1.
pub fn build_html5(user: &str, pass: &str, nonce: [u8; 4], slot: u8) -> Result<Vec<u8>> {
    validate_tokens(user, pass)?;
    if slot > 2 {
        return Err("slot must be in 0..=2".into());
    }
    let mut body = plug_in_body(user, pass, nonce, slot);
    body[40] = 0xc0 | 0x80 | 1 | ((slot + 1) << 1);
    body.extend(descriptors_html5());
    let mut packet = vec![0, 0, 0, 1, 44, 0, 0, 0];
    packet.extend(body);
    Ok(packet)
}

fn plug_in_body(user: &str, pass: &str, nonce: [u8; 4], slot: u8) -> Vec<u8> {
    let mut body = vec![0; 44];
    body[..user.len()].copy_from_slice(user.as_bytes());
    body[16..16 + pass.len()].copy_from_slice(pass.as_bytes());
    body[36..40].copy_from_slice(&nonce);
    body[40] = 0x81 | ((slot + 1) << 1);
    body[41] = 3;
    body
}

/// The reference uses rand() serialized BE, not a cryptographic challenge.
/// Linux entropy avoids shared libc srand/rand state and stays in RAND_MAX.
pub fn nonce() -> Result<[u8; 4]> {
    use std::io::Read;
    let mut bytes = [0; 4];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    bytes[0] &= 0x7f;
    Ok(bytes)
}

/// The HTML5 client draws `Math.floor(Math.random()*32768)`, a 15-bit field.
pub fn nonce_html5() -> Result<[u8; 4]> {
    Ok((u32::from_be_bytes(nonce()?) & 0x7fff).to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn rc4_known_answer() {
        let mut data = b"Plaintext".to_vec();
        rc4(&mut data, b"Key");
        assert_eq!(data, hex("bbf316e8d940af0ad3"));
    }
    #[test]
    fn matches_frame_33_byte_for_byte() {
        let expected = hex(concat!(
            "008000012c000000e7e948c60356a54650b1628186d186e7b0ff8cf14a4dfb25",
            "cffb8dd29844ed2ae9ca4d2d83a994856abe552f246b1093195ca74a9dadf767",
            "6d2afcb4bea8fda23673acfcd4f214b9c9c1da3f761adccf522de2853675576a",
            "189503cb67850e15246af54cdbf6cf8b7a3ce093cc101c9662398e2fa3cebfc1",
            "a32e175953de0ee70bf8ae58cc82c31fb45b4717298c80ca1abab6fd4c722cae",
            "cad5efd9fe7ace771141df0d86adf2f3f81e0f23587624e8a6fdf136506e5f14",
            "3025e303f7add81014c6988a9a5f363f68190ac06fda757c44192bb2b0a79cfe",
            "97b6"
        ));
        let actual = build("VV9mwNmqvN/y1xb", "iodJo2Q==", [0x5a, 0xf4, 0x5c, 4], 0).unwrap();
        assert_eq!(actual.len(), 226);
        assert_eq!(actual, expected);
    }
    #[test]
    fn rejects_bad_tokens_and_slot() {
        assert!(build("12345678901234567", "a", [0; 4], 0).is_err());
        assert!(build("a", "bad\0token", [0; 4], 0).is_err());
        assert!(build("a", "b", [0; 4], 3).is_err());
        assert!(build_html5("12345678901234567", "a", [0; 4], 0).is_err());
        assert!(build_html5("a", "b", [0; 4], 3).is_err());
    }
    #[test]
    fn html5_packet_is_clear_with_insyde_control_byte() {
        let packet = build_html5("fwhXSuKINlBYFEv", "GagTTXA==", [0, 0, 0x12, 0x34], 0).unwrap();
        assert_eq!(packet.len(), 226);
        // Header: clear (no ENCRYPT_RC4 bit), command 1, 44-byte body.
        assert_eq!(&packet[..8], &[0, 0, 0, 1, 44, 0, 0, 0]);
        assert_eq!(&packet[8..23], b"fwhXSuKINlBYFEv");
        assert_eq!(&packet[24..33], b"GagTTXA==");
        assert_eq!(&packet[44..48], &[0, 0, 0x12, 0x34]);
        // totalDevNumber 1 | SID auth 0x80 | HTML5 0x40 | slot<<1.
        assert_eq!(packet[48], 0xc3);
        assert_eq!(packet[49], 3);
        assert_eq!(build_html5("a", "b", [0; 4], 1).unwrap()[48], 0xc5);
        assert_eq!(build_html5("a", "b", [0; 4], 2).unwrap()[48], 0xc7);
        // HTML5 VID/PID patch (0x0b1f / 0x03ea) in the device descriptor record.
        assert_eq!(&packet[61..65], &[0x1f, 0x0b, 0xea, 0x03]);
        // "Flash Disk" + 6 spaces (UTF-16LE), then the same serial string as
        // the capture.
        assert_eq!(&packet[117..151], &usb_string("Flash Disk      ")[..]);
        assert_eq!(&packet[152..186], &usb_string("4E8F092C3FD7F8F7")[..]);
    }
    #[test]
    fn html5_nonce_is_fifteen_bit() {
        let nonce = nonce_html5().unwrap();
        assert_eq!(&nonce[..2], &[0, 0]);
        assert!(nonce[2] & 0x80 == 0);
    }
}
