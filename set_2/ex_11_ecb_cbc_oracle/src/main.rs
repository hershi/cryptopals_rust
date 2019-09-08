#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use utils::*;
use utils::encryption::*;
use utils::english_scoring::*;
use rand::prelude::*;

const BLOCK_SIZE : usize = 16;
const KEY_SIZE : usize = 16;
const IV_SIZE : usize = 16;

#[derive(Debug, Eq, PartialEq)]
enum EncryptionMode {
    CBC,
    ECB
}

lazy_static! {
    pub static ref UNIFORM_DIST: HashMap<u8, f32> = {
        let mut dist = HashMap::new();
        for b in 0..255u8 {
            dist.insert(b, 1f32/255f32);
        }
        dist
    };
}

fn read_input() -> String {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
        .join("")
}

fn encryption_oracle(input: &[u8]) -> (Vec<u8>, EncryptionMode) {
    let key = random_buffer(KEY_SIZE);

    let input = add_pre_post_fixes(input);

    let use_cbc = random();
    if use_cbc {
        (cbc_encrypt(&input, &key, random_buffer(IV_SIZE)), EncryptionMode::CBC)
    } else {
        (ecb_encrypt(&input, &key), EncryptionMode::ECB)
    }
}

fn add_pre_post_fixes(input: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let prefix_size = rng.gen_range(5,11);
    let postfix_size = rng.gen_range(5,11);

    let prefix = random_buffer(prefix_size);
    let postfix = random_buffer(postfix_size);
    prefix.iter()
        .chain(input)
        .chain(&postfix)
        .cloned()
        .collect()
}

fn encryption_mode_oracle(encrypted_data: &[u8]) -> EncryptionMode {
    let is_cbc = is_cbc(encrypted_data);
    let is_ecb = is_ecb(encrypted_data);

    assert!(is_ecb != is_cbc);

    if (is_ecb) { EncryptionMode::ECB } else { EncryptionMode::CBC}
}

fn is_cbc(encrypted_data: &[u8]) -> bool {
    score(&encrypted_data, &UNIFORM_DIST) < 1f32
}

fn is_ecb(input: &[u8]) -> bool {
    let mut freq = HashMap::new();

    for chunk in input.chunks(BLOCK_SIZE) {
        *freq.entry(chunk).or_insert(0) += 1
    }

    let res = freq.values().any(|v| *v > 1);
    res
}

fn score(input: &[u8], expected_frequencies: &HashMap<u8, f32>) -> f32 {
    let mut frequencies = get_byte_frequencies(input);

    let length = input.len() as f32;
    for (_, v) in frequencies.iter_mut() {
        *v = *v / length;
    }

    expected_frequencies.iter()
        .map(|(k,v)| {
            let freq = frequencies.get(&k).unwrap_or(&0f32);
            (v - freq).abs() })
        .sum()
}

fn main() {
    let input = read_input();
    let input_bytes = input.as_bytes();
    for i in 0..50 {
        let (encrypted, mode) = encryption_oracle(&input_bytes);
        let oracle_prediction = encryption_mode_oracle(&encrypted);
        println!("{}: Prediction correct? {}; {:?}: Oracle says - {:?}",
                 i,
                 oracle_prediction == mode,
                 mode,
                 oracle_prediction);
    }
}

