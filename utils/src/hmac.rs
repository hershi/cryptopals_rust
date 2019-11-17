use super::sha1::*;
use std::iter;

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

    let inner_data =
        key.iter()
        .map(|b| b ^ IPAD_BYTE)
        .chain(data.iter().cloned())
        .collect::<Vec<u8>>();

    let inner = sha1(&inner_data);

    let outer_data =
        key.iter()
        .map(|b| b ^ OPAD_BYTE)
        .chain(inner.iter().cloned())
        .collect::<Vec<u8>>();

    sha1(&outer_data)
}
