#[macro_use]
extern crate lazy_static;

use utils::*;
use utils::encoding::*;
use utils::encryption::*;

const BLOCK_SIZE : usize = 16;
const KEY_SIZE : usize = 16;
const IV_SIZE : usize = 16;

const PREFIX : &[u8] = b"comment1=cooking%20MCs;userdata=";
const SUFFIX : &[u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
    pub static ref IV: Vec<u8> = random_buffer(IV_SIZE);
}

fn sanitize(user_data: &[u8]) -> Vec<u8> {
    user_data.iter()
        .fold(vec![], |mut acc, &b| {
            let c = b as char;
            if c == ';' || c == '=' {
                acc.push(b'"');
                acc.push(b);
                acc.push(b'"');
                return acc;
            }

            acc.push(b);
            acc
        })
}

fn generate_input(user_data: &[u8]) -> Vec<u8> {
    let user_data = sanitize(user_data);
    let input = PREFIX.iter()
        .chain(&user_data)
        .chain(SUFFIX.iter())
        .cloned()
        .collect();

    pad_block(input, BLOCK_SIZE as u8)
}

fn oracle(user_data: &[u8]) -> Vec<u8> {
    let input = generate_input(user_data);
    cbc_encrypt(&input, &KEY, IV.clone())
}

fn validator(encrypted: &[u8]) -> bool {
    let decrypted = cbc_decrypt(encrypted, &KEY, &IV);
    let decrypted_string = to_string(&decrypted);
    println!("Decrypted: {}", decrypted_string);

    decrypted_string.contains(";admin=true;")
}

fn main() {
    println!("{}", to_string(&generate_input(b";admin=true;")));

    let encrypted = oracle(b";admin=true;");

    println!("Result: {}", validator(&encrypted));
}
