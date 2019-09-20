#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use data_encoding::BASE64;
use utils::*;
use utils::encoding::*;
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

fn build_decryption_table(prefix: &[u8]) -> HashMap<Vec<u8>, u8> {
    assert_eq!(prefix.len() + 1, *BLOCK_SIZE);

    let mut table = HashMap::new();
    for i in 0..255u8 {
        let mut block = prefix.to_vec();
        block.push(i);
        let mut encrypted = encryption_oracle(&block);
        encrypted.truncate(prefix.len() + 1);
        table.insert(encrypted, i);
    }

    table
}

fn get_prefix_size(byte_index: usize) -> usize {
    *BLOCK_SIZE - (byte_index % *BLOCK_SIZE) - 1
}

fn build_encryption_cache() -> HashMap<usize, Vec<u8>> {
    let prefix_buffer = vec![0u8; *BLOCK_SIZE - 1];
    let mut cache = HashMap::new();
    for i in 0..*BLOCK_SIZE {
        cache.insert(i, encryption_oracle(&prefix_buffer[0..i]));
    }

    cache
}

fn decrypt() -> String {
    let mut result = Vec::with_capacity(UNKNOWN_INPUT.len() + *BLOCK_SIZE);
    result.resize(*BLOCK_SIZE, 0u8);

    let cache = build_encryption_cache();

    for byte_index in 0..UNKNOWN_INPUT.len() {
        let decryption_table =
            build_decryption_table(&result[result.len()-*BLOCK_SIZE+1..]);

        let prefix_size = get_prefix_size(byte_index);
        let encrypted = cache.get(&prefix_size).unwrap();
        let block_index = byte_index / *BLOCK_SIZE;
        let block_start = block_index * *BLOCK_SIZE;
        let block_end = block_start + *BLOCK_SIZE;
        let b = decryption_table.get(&encrypted[block_start..block_end]).unwrap();
        result.push(*b);
    }

    to_string(&result)
}

fn main() {
    println!("Block size: {}", *BLOCK_SIZE);
    println!("Encryption mode: {:?}", find_encryption_mode());
    println!("Decrypted: {}", decrypt());
}
