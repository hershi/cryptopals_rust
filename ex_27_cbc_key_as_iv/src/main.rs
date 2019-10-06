#[macro_use]
extern crate lazy_static;

use utils::*;
use utils::encryption::*;

const BLOCK_SIZE : usize = 16;
const KEY_SIZE : usize = 16;

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
}

fn oracle(input: &[u8]) -> Vec<u8> {
    cbc_encrypt(input, &KEY, KEY.clone(), true)
}

fn validator(encrypted: &[u8]) -> Result<(), Vec<u8>> {
    let decrypted = cbc_decrypt(encrypted, &KEY, &KEY, true);

    if decrypted.iter().all(|b| b.is_ascii()) {
        Ok(())
    } else {
        Err(decrypted)
    }
}

fn main() {
    let input = [b'A'; BLOCK_SIZE * 3];
    let encrypted = oracle(&input);
    let first_block = encrypted.as_slice().chunks(BLOCK_SIZE).nth(0).unwrap();
    let last_block = encrypted.as_slice().chunks(BLOCK_SIZE).last().unwrap();

    let mut attack = Vec::with_capacity(encrypted.len());
    attack.extend_from_slice(first_block);
    attack.extend_from_slice(&[0u8;BLOCK_SIZE]);
    attack.extend_from_slice(first_block);
    attack.extend_from_slice(last_block);

    let result = validator(&attack);

    let decrypted = result.unwrap_err();
    let p1 = &decrypted.as_slice()[0..BLOCK_SIZE];
    let p3 = &decrypted.as_slice()[BLOCK_SIZE*2..BLOCK_SIZE*3];
    let key = xor(&p1,&p3);

    println!("Extracted key {:?}\nMatches key? {}",
             key,
             key == *KEY);
}
