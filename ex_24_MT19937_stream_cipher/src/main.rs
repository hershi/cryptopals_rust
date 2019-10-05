#[macro_use]
extern crate lazy_static;

use rand::prelude::*;
use utils::*;
use utils::mt19937::*;
use std::iter::*;

lazy_static! {
    static ref PREFIX: Vec<u8> = {
        let mut rng = thread_rng();
        let prefix_size = rng.gen_range(1, 10000);
        random_buffer(prefix_size)
    };
}

fn mt_encrypt(seed: u16, input:&[u8]) -> Vec<u8> {
    let mut mt = MersenneTwister::new(seed.into());

    input.chunks(4)
        .zip(repeat_with(|| mt.extract_number().to_le_bytes().to_vec()))
        .map(|(input_bytes, key_bytes)| xor(input_bytes, &key_bytes))
        .flat_map(|encrypted_bytes| encrypted_bytes)
        .collect()
}

fn mt_decrypt(seed: u16, input:&[u8]) -> Vec<u8> {
    mt_encrypt(seed, input)
}

fn create_input(input: &[u8]) -> Vec<u8> {
    PREFIX.iter().chain(input.iter()).cloned().collect()
}

fn crack_seed(encrypted: &[u8], known_plaintext: &[u8]) -> Option<u16> {
    (u16::min_value()..=u16::max_value())
        .map(|key| (key, mt_decrypt(key, encrypted)))
        .find(|(_, decrypted)| decrypted.ends_with(known_plaintext))
        .map(|(key,_)| key)
}

//fn generate_reset_token(username: &[u8]) -> Vec<u8> {
//}

fn main() {
    let seed = random::<u16>();

    println!("Prefix size is {}", PREFIX.len());
    println!("Seed is {}", seed);

    let input = [b'A'; 14];
    let encrypted = mt_encrypt(seed, &create_input(&input));

    let cracked_seed = crack_seed(&encrypted, &input);
    println!("seed/cracked_seed: {}:{:?} Same? {}",
             seed,
             cracked_seed,
             Some(seed) == cracked_seed);
}
