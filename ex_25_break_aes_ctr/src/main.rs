#[macro_use]
extern crate lazy_static;

use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use utils::*;
use data_encoding::BASE64;
use openssl::symm::{decrypt, Cipher};

const ECB_KEY : &[u8] = b"YELLOW SUBMARINE";
const KEY_SIZE : usize = 16;

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

fn main() {
    let plaintext = read_input();
}
