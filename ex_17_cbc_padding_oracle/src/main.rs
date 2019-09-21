#[macro_use]
extern crate lazy_static;

use rand::prelude::*;
use utils::*;
use utils::encryption::*;

const BLOCK_SIZE : usize = 16;
const KEY_SIZE : usize = 16;
const IV_SIZE : usize = 16;

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);

    pub static ref INPUT_STRINGS : Vec<&'static str> = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        //"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        //"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        //"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        //"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        //"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        //"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        //"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        //"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        //"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
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
    for b in 0..=255 {
        let mut iv = iv.to_vec();
        iv[byte_index] ^= b;

        if !decrypt_and_validate_padding(input_block, &iv) {
            continue;
        }

        println!("{} Possible: {}", byte_index, b);
        if byte_index == 0 { return b; }

        iv[byte_index - 1] ^= 1;
        if !decrypt_and_validate_padding(input_block, &iv) {
            println!("Previous byte changes - {} is not a good option", b);
            continue;
        }

        return b;
    }

    0
}

fn prep_iv(iv: &[u8], byte_index: usize, cracked_block: &[u8]) -> Vec<u8> {
    let padding = (BLOCK_SIZE - byte_index) as u8;
    iv.iter()
        .zip(cracked_block.iter())
        .enumerate()
        .map(|(i, (&iv_byte,&block_byte))| {
            if i > byte_index {
                iv_byte ^ block_byte ^ padding
            } else {
                iv_byte
            }})
        .collect()
}

fn crack_cbc_block(input_block: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut cracked_block = vec![0; BLOCK_SIZE];
    for byte_index in 0..BLOCK_SIZE {
        let byte_index = BLOCK_SIZE - 1 - byte_index;
        let padding = BLOCK_SIZE - byte_index;

        let iv = prep_iv(iv, byte_index, &cracked_block);

        let byte_mask = crack_cbc_byte(input_block, &iv, byte_index);
        cracked_block[byte_index] = byte_mask ^ padding as u8;
        println!("Byte {}, {}", byte_index, cracked_block[byte_index]);
    }

    cracked_block
}

fn main() {
    let encrypted = encryption_oracle();
    crack_cbc_block(encrypted.encrypted_data.chunks(BLOCK_SIZE).nth(0).unwrap(), &encrypted.iv);
}
