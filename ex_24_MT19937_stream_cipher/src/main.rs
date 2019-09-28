use rand::prelude::*;
use utils::*;
use utils::encoding::*;
use utils::mt19937::*;
use std::iter::*;

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

fn main() {
    let seed = random::<u16>();
    let encrypted = mt_encrypt(seed, b"HELLLO WORLD");
    let decrypted = mt_encrypt(seed, &encrypted);
    println!("Enc: {:?}", encrypted);
    println!("Enc: {:?}", to_string(&decrypted));
}
