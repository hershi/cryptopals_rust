#[macro_use]
extern crate lazy_static;

use utils::*;
use utils::hash_utils::*;
use utils::sha1::*;

const KEY_SIZE : usize = 16;
const MESSAGE : &[u8] = b"hello world";

lazy_static! {
    //pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
    pub static ref KEY: Vec<u8> = vec![11;16];
}

fn secret_prefix_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let prefixed_message =
        key.iter().chain(message.iter())
        .cloned()
        .collect::<Vec<u8>>();

    sha1(&prefixed_message)
}

fn main() {
    println!("KEY: {:?}", *KEY);
    println!("Message: {:?}", MESSAGE);
    print_hash(&secret_prefix_mac(&KEY, &MESSAGE));
}
