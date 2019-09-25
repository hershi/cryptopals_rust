#[macro_use]
extern crate lazy_static;

use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use utils::*;
use utils::encoding::*;
use utils::encryption::*;
use utils::repeating_xor_cracker::*;
use data_encoding::BASE64;

const KEY_SIZE : usize = 16;

lazy_static! {
    static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
}

fn read_input() -> Vec<Vec<u8>> {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    reader.lines()
        .map(|line| line.unwrap())
        .map(|line| BASE64.decode(line.as_bytes()).unwrap())
        .map(|input| ctr_encrypt(&input, &KEY, 0))
        .collect()
}

fn main() {
    let inputs = read_input();
    let common_length = inputs.iter()
        .map(|input| input.len())
        .min()
        .unwrap();

    println!("Common Length: {}", common_length);

    let input_for_repeating_xor = inputs.iter()
        .flat_map(|input| input.iter().take(common_length))
        .cloned()
        .collect::<Vec<u8>>();

    println!("Input for repeating xor {:?}", input_for_repeating_xor);

    let key = find_xor_key(&input_for_repeating_xor, common_length);
    println!("Repeating xor key {:?}", key);

    for input in inputs {
        let mut decrypted = xor(&input, &key);
        decrypted.truncate(common_length);
        let gap  = input.len() - decrypted.len();
        println!("Decrypted (gap {}): {}", gap, to_string(&decrypted));
    }
}
