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
    let records: Vec<Vec<u8>> = vec![
        vec![
            0x12, 1, 0, 2, 0, 0, 0, 0x40, 0xa0, 0x0e, 0x11, 0x11, 0, 2, 0, 0, 0, 1,
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
    ];
    for r in records {
        result.push(r.len() as u8);
        result.extend(r);
    }
    result
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
    let mut body = vec![0; 44];
    body[..user.len()].copy_from_slice(user.as_bytes());
    body[16..16 + pass.len()].copy_from_slice(pass.as_bytes());
    body[36..40].copy_from_slice(&nonce);
    body[40] = 0x81 | ((slot + 1) << 1);
    body[41] = 3;
    body.extend(descriptors());
    rc4(&mut body, KEY);
    let mut packet = vec![0, 0x80, 0, 1, 44, 0, 0, 0];
    packet.extend(body);
    Ok(packet)
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
    }
}
