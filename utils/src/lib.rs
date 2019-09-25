#[macro_use]
extern crate lazy_static;

pub mod english_scoring;
pub mod encoding;
pub mod encryption;
pub mod repeating_xor_cracker;

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

pub fn validate_padding(input: &[u8], block_size: usize) -> Result<(), &str> {
    if input.len() == 0 {
        return Err("bad padding - empty input");
    }

    let last_byte = *input.last().unwrap() as usize;
    if last_byte > block_size {
        return Err("bad padding - last byte too big");
    }

    if last_byte <= 0 {
        return Err("bad padding - last byte too small");
    }

    // Last byte is less than block size. Let's see if all the `last_byte` bytes
    // have that value
    let last_block = input.chunks(block_size).last().unwrap();
    if last_block.iter()
            .skip(block_size - last_byte as usize)
            .any(|&b| b != last_byte as u8) {
        return Err("bad padding - some bytes with wrong value");
    }

    Ok(())
}

pub fn strip_padding(input: &mut Vec<u8>, block_size: usize) {
    assert!(validate_padding(input, block_size).is_ok());
    let last_byte = *input.last().unwrap() as usize;
    input.truncate(input.len() - last_byte);
}

pub fn random_buffer(size: usize) -> Vec<u8> {
    std::iter::repeat_with(|| rand::random::<u8>())
        .take(size)
        .collect()
}

