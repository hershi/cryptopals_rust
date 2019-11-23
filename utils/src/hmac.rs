use super::sha1::*;
use super::xor;

const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5C;
const BLOCK_SIZE: usize = 64;

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    // If the key is too long, hash it
    let mut key = if key.len() > BLOCK_SIZE {
        sha1(key)
    } else {
        key.to_vec()
    };

    assert!(key.len() <= BLOCK_SIZE);

    // Pad the key with 0s if needed to get to block size
    key.resize(BLOCK_SIZE, 0);

    assert!(key.len() == BLOCK_SIZE);

    let inner = sha1(
        &(xor(&key, &[IPAD_BYTE]).iter()
        .chain(data.iter())
        .cloned()
        .collect::<Vec<u8>>()));

    sha1(
        &(xor(&key, &[OPAD_BYTE]).iter()
        .chain(inner.iter())
        .cloned()
        .collect::<Vec<u8>>()))
}
