#[macro_use]
extern crate lazy_static;

use utils::*;
use utils::encoding::*;
use utils::encryption::*;

const BLOCK_SIZE : usize = 16;
const IV_SIZE : usize = 16;
const IV : [u8; IV_SIZE] = [0; IV_SIZE];

lazy_static! {
    pub static ref KEY: &'static[u8] = "YELLOW SUBMARINE".as_bytes();
}

fn ctr_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    input.chunks(BLOCK_SIZE)
        .zip(0u128..)
        .map(|(block, counter)| {
            let key_stream = cbc_encrypt(&counter.to_le_bytes(), key, iv.to_vec(), false);
            xor(block, &key_stream)})
        .fold(
            Vec::with_capacity(input.len()),
            |mut acc, mut block| { acc.append(&mut block); acc})
}

fn ctr_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    ctr_encrypt(input, key, iv)
}

fn main() {
    let encrypted = ctr_encrypt("Abcd".as_bytes(), &KEY, &IV);
    println!("{:?}", encrypted);

    let decrypted = ctr_decrypt(&encrypted, &KEY, &IV);
    println!("{:?}", decrypted);
    println!("{:?}", to_string(&decrypted));
}
