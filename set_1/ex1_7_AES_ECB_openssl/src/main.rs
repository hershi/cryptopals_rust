use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use data_encoding::BASE64;
use openssl::symm::{decrypt, Cipher};

fn read_input() -> Vec<u8> {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    let input_string = reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
        .join("");

    BASE64.decode(input_string.as_bytes()).unwrap()
}

fn main() {
    let cipher = Cipher::aes_128_ecb();
    let key = "YELLOW SUBMARINE".as_bytes();
    let plaintext_bytes = decrypt(
        cipher,
        key,
        None,
        &read_input()).unwrap();

    let plaintext = String::from_utf8(plaintext_bytes).unwrap();

    println!("Decrypted message: {}", plaintext);
}
