#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::iter::repeat;
use utils::*;
use utils::encoding::*;
use utils::encryption::*;

const KEY_SIZE : usize = 16;
const PREFIX : &[u8] = b"email=";
const SUFFIX : &[u8] = b"&uid=10&role=user";

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
}

fn parse_key_values(input: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for kv_str in input.split('&') {
        let parts = kv_str.split('=').collect::<Vec<_>>();
        if parts.len() != 2 { continue; }
        map.insert(parts[0].to_string(), parts[1].to_string());
    }

    map
}

fn profile_for(input: &[u8]) -> Vec<u8> {
    PREFIX.iter()
        .chain(
            input.iter()
                .filter(|&&b| {
                    let c = b as char;
                    c != '&' && c != '='}))
        .chain(SUFFIX.iter())
        .cloned()
        .collect()
}

fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let profile = profile_for(input);
    ecb_encrypt(&profile, &KEY)
}

fn decrypt_profile(profile: &[u8]) -> String {
    to_string(&ecb_decrypt(profile, &KEY))
}

fn main() {
    let mut email = b"admin".to_vec();
    println!("profile_for({}): {}",
        to_string(&email),
        to_string(&profile_for(&email)));

    let original_size = encryption_oracle(&email).len();

    let mut encrypted = encryption_oracle(&email);
    while encrypted.len() == original_size {
        email.insert(0, b'_');
        encrypted = encryption_oracle(&email);
    }

    let block_size = encrypted.len() - original_size;

    // We're at the boundary where a new block was added. Given how
    // PKCS#7 padding works, this means that the new block is all
    // padding.
    //
    // 1. Store the (encrypted) padding block - we'll need it later when we
    // truncate an encrypted output at the block boundary and need to add
    // a padding block (otherwise decryption fails)
    let padding_block = encrypted
        .as_slice()
        .chunks(block_size)
        .last()
        .map(|chunk| chunk.to_vec())
        .unwrap();

    // 2. Insert 4 more characters at the beginning to push out the 'user'
    // portion of 'email=foo@bar.com&uid=10&role=user' to be in the last block.
    // This means that if we take the encrypted blocks without the last one,
    // we get something like 'email=...&role='
    email = b"____".iter().chain(email.iter()).cloned().collect();
    encrypted = encryption_oracle(&email);

    // Take everything other than the last block, and we get
    // 'email=...role=' without 'user'. Now we just need to get
    // a block with 'admin<padding>' and concatenate the two
    let without_last_block = encrypted.len() - block_size;
    let prefix = encrypted[0..without_last_block].to_vec();

    // Now to create a block with 'admin<padding>':
    // Create an input that's 'admin<padding>', then add a prefix
    // before 'admin' that will push it to be at the beginning of a
    // block.
    let padded_admin = pad_block(b"admin".to_vec(), block_size as u8);
    println!("Padded admin: {:?}", padded_admin);

    let pre_padding_needed = block_size - PREFIX.len();
    let padded_email = repeat(&b'_')
        .take(pre_padding_needed)
        .chain(padded_admin.iter())
        .cloned()
        .collect::<Vec<_>>();
    println!("Padded admin: {:?}", profile_for(&padded_email));

    let encrypted = encryption_oracle(&padded_email);
    let padded_admin_block = encrypted
        .as_slice()
        .chunks(block_size)
        .nth(1)
        .unwrap()
        .to_vec();

    let mut crafted = prefix.clone();
    crafted.append(&mut prefix.clone());
    crafted.append(&mut padded_admin_block.clone());

    let decrypted_crafted = decrypt_profile(&crafted);
    let parsed_crafted = parse_key_values(&decrypted_crafted);
    println!("Crafted - string: {:?}", decrypted_crafted);
    println!("Crafted - Object: {:?}", parsed_crafted);
}
