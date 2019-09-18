#[macro_use]
extern crate lazy_static;

use utils::*;
use utils::encoding::*;
use utils::encryption::*;

const BLOCK_SIZE : usize = 16;
const KEY_SIZE : usize = 16;

const PREFIX : &[u8] = b"comment1=cooking%20MCs;userdata=";
const SUFFIX : &[u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
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
    PREFIX.iter()
        .chain(&user_data)
        .chain(SUFFIX.iter())
        .cloned()
        .collect()
}

fn main() {
    println!("{}", to_string(&generate_input(b";admin=true;")));
}
