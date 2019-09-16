#[macro_use]
extern crate lazy_static;

use rand::prelude::*;
use std::collections::HashMap;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use data_encoding::BASE64;
use utils::*;
use utils::encoding::*;
use utils::encryption::*;

const BLOCK_SIZE : usize = 16;
const KEY_SIZE : usize = 16;
const ALIGNMENT_VALUE : u8 = 255;
const SEPARATOR_VALUE : u8 = 244;
const PREPADDING_VALUE : u8 = 1;

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
    pub static ref UNKNOWN_INPUT: Vec<u8> = read_input();
}

fn build_input(input: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let prefix_size = rng.gen_range(0,1000);

    let prefix = random_buffer(prefix_size);
    prefix.iter()
        .chain(input)
        .chain(UNKNOWN_INPUT.iter())
        .cloned()
        .collect()
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

fn build_decryption_table(prefix: &[u8]) -> HashMap<Vec<u8>, u8> {
    assert_eq!(prefix.len() + 1, BLOCK_SIZE);

    let mut table = HashMap::new();
    for i in 0..=255u8 {
        let mut block = prefix.to_vec();
        block.push(i);
        let mut encrypted = get_aligned_encryption(&block).unwrap();
        encrypted.truncate(prefix.len() + 1);
        table.insert(encrypted, i);
    }

    table
}

fn build_block_freq(encrypted: &[u8]) -> HashMap<&[u8], usize> {
    let mut freq = HashMap::new();

    for chunk in encrypted.chunks(BLOCK_SIZE) {
        *freq.entry(chunk).or_insert(0) += 1
    }

    freq
}

fn get_aligned_encryption(prefix: &[u8]) -> Result<Vec<u8> ,String> {
    const NUM_ALIGNMENT_BLOCKS :usize = 3;

    for _ in 0..1000 {
        let prefix = build_prefix(prefix, NUM_ALIGNMENT_BLOCKS);
        let encrypted = encryption_oracle(&prefix);
        let block_freq = build_block_freq(&encrypted);
        if let Some((alignment_block,_)) = block_freq
            .iter()
            .find(|(_, &v)| v == NUM_ALIGNMENT_BLOCKS) {
            return Ok(encrypted
                .chunks(BLOCK_SIZE)
                .skip_while(|block| block != alignment_block)
                .skip(NUM_ALIGNMENT_BLOCKS)
                .flat_map(|block| block.to_vec())
                .collect::<Vec<u8>>())
        }
    }

    Err(format!("Couldn't generate encryption with prefix {:?}", prefix))
}

fn build_prefix(desired_prefix: &[u8], num_alignment_blocks: usize) -> Vec<u8> {
    // Why do we need the SEPARATOR_VALUE?
    // Otherwise, we can get into a state where the last byte of the random
    // prefix is the same as ALIGNMENT_VALUE. In such a case, even if we're
    // misaligned by one-byte to the right, we won't detect that, because there
    // is no way for us to differentiate between the random prefix and our
    // alignment blocks. By adding a "separator" block with a different byte
    // value, we can make this detectable
    let mut prefix = vec![SEPARATOR_VALUE; BLOCK_SIZE];
    prefix.append(&mut vec![ALIGNMENT_VALUE; BLOCK_SIZE * num_alignment_blocks]);
    prefix.extend_from_slice(desired_prefix);
    prefix
}

fn get_prefix_size(byte_index: usize) -> usize {
    BLOCK_SIZE - (byte_index % BLOCK_SIZE) - 1
}

fn build_encryption_cache() -> HashMap<usize, Vec<u8>> {
    let prefix_buffer = vec![PREPADDING_VALUE; BLOCK_SIZE - 1];
    let mut cache = HashMap::new();
    for i in 0..BLOCK_SIZE {
        cache.insert(i, get_aligned_encryption(&prefix_buffer[0..i]).unwrap());
    }

    cache
}

fn decrypt() -> String {
    let mut result = vec!(PREPADDING_VALUE; BLOCK_SIZE);

    let cache = build_encryption_cache();

    for byte_index in 0.. {
        let decryption_table =
            build_decryption_table(&result[result.len()-BLOCK_SIZE+1..]);

        let prefix_size = get_prefix_size(byte_index);
        let encrypted = cache.get(&prefix_size).unwrap();
        let block_index = byte_index / BLOCK_SIZE;
        let block_start = block_index * BLOCK_SIZE;
        let block_end = block_start + BLOCK_SIZE;
        if let Some(b) = decryption_table.get(&encrypted[block_start..block_end]) {
            result.push(*b);
        } else {
            println!("Breaking at byte {} (encrypted length {})", byte_index, encrypted.len());
            break;
        }
    }

    to_string(&result)
}

fn encryption_oracle(my_input: &[u8]) -> Vec<u8> {
    let input = build_input(my_input);
    ecb_encrypt(&input, &KEY)
}

fn main() {
    let decrypted = decrypt();
    println!("Decrypted message:\n{}", decrypted);
}
