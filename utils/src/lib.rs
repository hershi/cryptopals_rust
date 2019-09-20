#[macro_use]
extern crate lazy_static;

pub mod english_scoring;
pub mod encoding;
pub mod encryption;

pub fn xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, key)| b^key)
        .collect()
}

pub fn pad_block(mut input: Vec<u8>, block_size: u8) -> Vec<u8> {

    let block_size: usize = block_size as usize;
    let last_block_size = input.len() % block_size;
    let padding_needed = block_size - last_block_size;
    input.resize(input.len() + padding_needed, padding_needed as u8);
    input
}

pub fn random_buffer(size: usize) -> Vec<u8> {
    std::iter::repeat_with(|| rand::random::<u8>())
        .take(size)
        .collect()
}

