#[macro_use]
extern crate lazy_static;

use rand::prelude::*;
use utils::*;
use utils::encoding::*;
use utils::encryption::*;
use data_encoding::BASE64;

const BLOCK_SIZE : usize = 16;
const KEY_SIZE : usize = 16;
const IV_SIZE : usize = 16;

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);

    pub static ref INPUT_STRINGS : Vec<&'static str> = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
}

fn choose_random_input() -> &'static str {
    let mut rng = thread_rng();
    let index = rng.gen_range(0, INPUT_STRINGS.len());
    INPUT_STRINGS[index]
}

#[derive(Debug)]
struct EncryptionOutput {
    encrypted_data: Vec<u8>,
    iv: Vec<u8>
}

fn encryption_oracle() -> EncryptionOutput {
    let input = choose_random_input();
    let input = pad_block(input.as_bytes().to_vec(), BLOCK_SIZE as u8);
    let iv = random_buffer(IV_SIZE);

    EncryptionOutput {
        encrypted_data: cbc_encrypt(&input, &KEY, iv.clone(), false),
        iv
    }
}

fn decrypt_and_validate_padding(encrypted_data: &[u8], iv: &[u8]) -> bool {
    let decrypted = cbc_decrypt(encrypted_data, &KEY, &iv.to_vec(), false);
    validate_padding(&decrypted, BLOCK_SIZE).is_ok()
}

fn crack_cbc_byte(input_block: &[u8], iv: &[u8], byte_index: usize) -> u8 {
    // For the padding to be valid, the byte index after decryption should be
    // equal to the number of bytes between byte_index and the end of the block
    // *inclusive*
    let padding = (BLOCK_SIZE - byte_index) as u8;
    for b in 0..=255 {
        let mut iv = iv.to_vec();
        iv[byte_index] ^= b;

        if !decrypt_and_validate_padding(input_block, &iv) {
            // Invalid padding - this is not the byte value we are looking for
            continue;
        }

        // It's a valid padding and we're not at the last byte of the block.
        // This means `b` achieves the right padding value
        if byte_index < BLOCK_SIZE - 1 { return b ^ padding; }

        // If we're at the last byte of the block, we need to handle the
        // following edge case:
        // If the value of the (plaintext) byte before last is 0x02, then we
        // can achieve valid padding if we flip the last byte of the block to
        // either 2 or 1... How do we know which one we hit?
        // If `b` yields the plaintext byte 0x01, then changing the previous
        // byte won't mess up the padding, otherwise, it will.
        //
        // Note that the same edge case exists if the bytes preceding the last
        // are 0x03 0x03, or 0x04 0x04 0x04, ...
        iv[byte_index - 1] ^= 1;
        if !decrypt_and_validate_padding(input_block, &iv) {
            continue;
        }

        return b ^ padding;
    }

    panic!("Failed to decrypt byte!");
}

// Create an IV that would cause the bytes starting at byte_index+1 to decrypt
// to `desired_value`
// BLOCK_SIZE - byte_index)
// To that end, we need to know the decrypted values of those bytes, which
// we receive in the relative positions in `cracked_block`. To cause them to
// decrypt to the value we want we just need to figure out which bits need
// to be flipped (bits_to_flip == desired_value ^ decrypted_byte_value) and then
// flip those bits in the original IV (== iv_byte ^ bits_to_flip)
fn prep_iv(
        iv: &[u8],
        byte_index: usize,
        cracked_block: &[u8],
        desired_value: u8) -> Vec<u8> {
    iv.iter()
        .zip(cracked_block.iter())
        .enumerate()
        .map(|(i, (&iv_byte, &block_byte))| {
            if i > byte_index {
                iv_byte ^ block_byte ^ desired_value
            } else {
                iv_byte
            }})
        .collect()
}

fn crack_cbc_block(input_block: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut cracked_block = vec![0; BLOCK_SIZE];
    for byte_index in 0..BLOCK_SIZE {
        // We start from the last byte of the block, working our way
        // backwards
        let byte_index = BLOCK_SIZE - 1 - byte_index;

        // The expected padding value if padding were to start at this byte
        // equals the number of bytes between here and the end of the block
        let padding = (BLOCK_SIZE - byte_index) as u8;

        // We want to start with an IV that causes the bytes following the
        // current byte decrypt to the padding value
        let iv = prep_iv(iv, byte_index, &cracked_block, padding);

        cracked_block[byte_index] = crack_cbc_byte(input_block, &iv, byte_index);
    }

    cracked_block
}

fn crack_cbc(encrypted_data: &[u8], iv: &[u8]) -> Vec<u8> {
    std::iter::once(iv)
        .chain(encrypted_data.chunks(BLOCK_SIZE))
        .zip(encrypted_data.chunks(BLOCK_SIZE))
        .map(|(iv, block)| crack_cbc_block(block, iv))
        .fold(Vec::new(), |mut acc, mut v| { acc.append(&mut v); acc })
}

fn main() {
    let encrypted = encryption_oracle();
    let mut plaintext = crack_cbc(&encrypted.encrypted_data, &encrypted.iv);
    strip_padding(&mut plaintext, BLOCK_SIZE);
    println!("{:?}", to_string(&plaintext));
    println!("{:?}", to_string(&BASE64.decode(&plaintext).unwrap()));
}
