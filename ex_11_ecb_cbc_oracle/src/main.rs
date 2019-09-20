use std::collections::HashMap;
use utils::*;
use utils::encryption::*;
use rand::prelude::*;

const BLOCK_SIZE : usize = 16;
const KEY_SIZE : usize = 16;
const IV_SIZE : usize = 16;

#[derive(Debug, Eq, PartialEq)]
enum EncryptionMode {
    CBC,
    ECB
}

fn encryption_oracle(input: &[u8]) -> (Vec<u8>, EncryptionMode) {
    let key = random_buffer(KEY_SIZE);

    let input = add_pre_post_fixes(input);

    let use_cbc = random();
    if use_cbc {
        (cbc_encrypt(&input, &key, random_buffer(IV_SIZE), true), EncryptionMode::CBC)
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

fn predicted_mode(input: &[u8]) -> EncryptionMode {
    let mut freq = HashMap::new();

    for chunk in input.chunks(BLOCK_SIZE) {
        *freq.entry(chunk).or_insert(0) += 1
    }

    if freq.values().any(|v| *v > 1) {
        EncryptionMode::ECB
    } else {
        EncryptionMode::CBC
    }
}

fn main() {
    // By using a known input that's repetitive, we can expect repeated blocks
    // in ECB, allowing for easy detection.
    let input = std::iter::repeat('A').take(1000).collect::<String>();
    let input_bytes = input.as_bytes();
    for i in 0..50 {
        let (encrypted, mode) = encryption_oracle(&input_bytes);
        let oracle_prediction = predicted_mode(&encrypted);
        println!("{}: Prediction correct? {}; {:?}: Oracle says - {:?}",
                 i,
                 oracle_prediction == mode,
                 mode,
                 oracle_prediction);
    }
}

