#[macro_use]
extern crate lazy_static;

use utils::*;
use utils::encoding::*;
use utils::encryption::*;
use data_encoding::BASE64;

const BLOCK_SIZE : usize = 16;
const IV_SIZE : usize = 16;
const IV : [u8; IV_SIZE] = [0; IV_SIZE];

const INPUT: &str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

lazy_static! {
    pub static ref KEY: &'static[u8] = "YELLOW SUBMARINE".as_bytes();
}

fn ctr_encrypt(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    input.chunks(BLOCK_SIZE)
        .zip(0u64..)
        .map(|(block, counter)| {
            let mut bytes = nonce.to_le_bytes().to_vec();
            bytes.extend_from_slice(&counter.to_le_bytes());
            println!("{:?}", bytes);
            let key_stream = cbc_encrypt(&bytes, key, IV.to_vec(), false);
            xor(block, &key_stream)})
        .fold(
            Vec::with_capacity(input.len()),
            |mut acc, mut block| { acc.append(&mut block); acc})
}

fn ctr_decrypt(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    ctr_encrypt(input, key, nonce)
}

fn main() {
    let encrypted = BASE64.decode(INPUT.as_bytes()).unwrap();
    let plaintext = ctr_decrypt(&encrypted, &KEY, 0);
    println!("{}", to_string(&plaintext));
}
