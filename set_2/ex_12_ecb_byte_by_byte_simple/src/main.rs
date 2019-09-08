#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use data_encoding::BASE64;
use utils::*;
use utils::encryption::*;

const KEY_SIZE : usize = 16;

#[derive(Debug, Eq, PartialEq)]
enum EncryptionMode {
    CBC,
    ECB
}

fn predicted_mode(input: &[u8], block_size: usize) -> EncryptionMode {
    let mut freq = HashMap::new();

    for chunk in input.chunks(block_size) {
        *freq.entry(chunk).or_insert(0) += 1
    }

    if freq.values().any(|v| *v > 1) {
        EncryptionMode::ECB
    } else {
        EncryptionMode::CBC
    }
}

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
    pub static ref UNKNOWN_INPUT: Vec<u8> = read_input();
    pub static ref BLOCK_SIZE : usize = find_block_size();
}

fn read_input() -> Vec<u8> {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    let input_string = reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
        .join("");

    BASE64.decode(input_string.as_bytes()).unwrap()
}

fn encryption_oracle(my_input: &[u8]) -> Vec<u8> {
    let input = my_input.iter()
        .chain(UNKNOWN_INPUT.iter())
        .cloned()
        .collect::<Vec<u8>>();
    ecb_encrypt(&input, &KEY)
}

fn find_block_size() -> usize {
    let original_size = encryption_oracle(&vec![]).len();
    for i in 1.. {
        let size = encryption_oracle(&vec![0; i]).len();
        if size - original_size > 0 {
            return (size - original_size) as usize
        }
    }

    assert!(false);
    return 0usize;
}

fn find_encryption_mode() -> EncryptionMode {
    let encrypted = encryption_oracle(&vec![0;1000]);
    predicted_mode(&encrypted, *BLOCK_SIZE)
}

//fn build_decryption_table(prefix: &[u8], block_size: usize) -> HashMap<Vec<u8>, u8> {
    //let mut table = HashMap::new();
    //for i in 0..255u8 {
        //let mut block = prefix.to_vec();
        //block.push(i);
        //let mut encrypted = encryption_oracle(&block);
        //encrypted.truncate(prefix.len() + 1);
        //table.insert(encrypted, i);
    //}

    //table
//}

//fn decrypt_byte() -> u8 {
//}

fn main() {
    println!("Block size: {}", *BLOCK_SIZE);
    println!("Encryption mode: {:?}", find_encryption_mode());
}
