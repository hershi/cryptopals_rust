#[macro_use]
extern crate lazy_static;

use rand::prelude::*;
use std::iter;
use std::time::Duration;
use std::thread;
use utils::*;
use utils::hash_utils::*;
use utils::hmac::*;


const DATA : &[u8] = b"The quick brown fox jumped over the lazy dog";
const KEY_SIZE : usize = 20;

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
}

fn validate_mac(data: &[u8], hmac: &[u8]) -> bool {
    let expected = hmac_sha1(&KEY, data);

    let delay = Duration::from_millis(50);
    hmac.iter()
        .zip(expected.iter())
        .all(|(a,b)| {
            thread::sleep(delay);
            a == b
        })
}

fn main() {
    let correct = hmac_sha1(&KEY, &DATA);
    let incorrect = hmac_sha1(&KEY, b"hello world");
    assert!(validate_mac(&DATA, &correct));
    assert!(!validate_mac(&DATA, &incorrect));
}
