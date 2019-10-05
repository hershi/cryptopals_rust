#[macro_use]
extern crate lazy_static;

use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use utils::*;
use utils::encryption::*;
use utils::encoding::*;
use data_encoding::BASE64;
use openssl::symm::{decrypt, Cipher};

const ECB_KEY : &[u8] = b"YELLOW SUBMARINE";
const KEY_SIZE : usize = 16;
const NONCE :u64 = 0;

lazy_static! {
    static ref KEY : Vec<u8> = random_buffer(KEY_SIZE);
}

fn read_input() -> Vec<u8> {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    let input_string = reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
        .join("");

    let input = BASE64.decode(input_string.as_bytes()).unwrap();

    decrypt(
        Cipher::aes_128_ecb(),
        ECB_KEY,
        None,
        &input).unwrap()
}

fn edit(ciphertext: &[u8],
        offset: usize,
        newtext: &[u8]) -> Vec<u8> {

    let mut plaintext = ctr_decrypt(ciphertext, &KEY, NONCE);
    plaintext.truncate(offset);
    plaintext.extend_from_slice(newtext);
    ctr_encrypt(&plaintext, &KEY, NONCE)
}

fn main() {
    let plaintext = read_input();
    let encrypted = ctr_encrypt(&plaintext, &KEY, NONCE);

    let my_text = vec![0u8; encrypted.len()];
    let edited_ciphertext = edit(&encrypted, 0, &my_text);

    let recovered_plaintext =
        xor(&xor(&encrypted, &edited_ciphertext), &my_text);

    println!("{}", to_string(&recovered_plaintext));
    println!("----------------------------\n{}", to_string(&recovered_plaintext));

    // Since 'my_text' is all 0's, xoring with it is a no-op, so we can drop it
    // in our case (but not if it had to be something other than 0's)
    let recovered_plaintext =
        xor(&encrypted, &edited_ciphertext);

    println!("{}", to_string(&recovered_plaintext));
    println!("----------------------------\n{}", to_string(&recovered_plaintext));

    // Or we can just recover the key stream based on the knowledge that
    // each `ciphertext_byte == (plaintext_byte ^ key_stream_byte)` and the fact
    // that we know the two other
    let key_stream = xor(&edited_ciphertext, &my_text);
    let recovered_plaintext = xor(&key_stream, &encrypted);
    println!("{}", to_string(&recovered_plaintext));
}
