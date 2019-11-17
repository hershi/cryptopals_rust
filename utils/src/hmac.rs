use super::sha1::*;
use std::iter;

const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5C;
const BLOCK_SIZE: usize = 64;

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    //let opad = iter::repeat(OPAD_BYTE).take(BLOCK_SIZE).collect();
    //let k1 = if key.len() > BLOCK_SIZE {
        //sha1(key)
    //} else {
    //};
    vec![]
}
