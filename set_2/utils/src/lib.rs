#[macro_use]
extern crate lazy_static;

pub mod english_scoring;
pub mod encoding;

pub fn xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, key)| b^key)
        .collect()
}
