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
        encrypted_data: cbc_encrypt(&input, &KEY, iv.clone()),
        iv
    }
}

fn decrypt_and_validate_padding(input: &EncryptionOutput) -> bool {
    let decrypted = cbc_decrypt(&input.encrypted_data, &KEY, &input.iv, false);
    validate_padding(&decrypted, BLOCK_SIZE).is_ok()
}

fn main() {
    let encrypted = encryption_oracle();
    println!("Validation result {}", decrypt_and_validate_padding(&encrypted));
}
