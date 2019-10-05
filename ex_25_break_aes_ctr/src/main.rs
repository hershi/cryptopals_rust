use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use data_encoding::BASE64;
use openssl::symm::{decrypt, Cipher};

const ECB_KEY : &[u8] = b"YELLOW SUBMARINE";

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

fn main() {
    let plaintext = read_input()
}
