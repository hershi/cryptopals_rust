#[macro_use]
extern crate lazy_static;

use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::collections::HashMap;
use data_encoding::BASE64;

lazy_static! {
    static ref EXPECTED_FREQUENCIES: HashMap<char, f32> = {
        [('a', 0.08167),
        ('b', 0.01492),
        ('c', 0.02782),
        ('d', 0.04253),
        ('e', 0.12702),
        ('f', 0.02228),
        ('g', 0.02015),
        ('h', 0.06094),
        ('i', 0.06966),
        ('j', 0.00153),
        ('k', 0.00772),
        ('l', 0.04025),
        ('m', 0.02406),
        ('n', 0.06749),
        ('o', 0.07507),
        ('p', 0.01929),
        ('q', 0.00095),
        ('r', 0.05987),
        ('s', 0.06327),
        ('t', 0.09056),
        ('u', 0.02758),
        ('v', 0.00978),
        ('w', 0.02360),
        ('x', 0.00150),
        ('y', 0.01974),
        ('z', 0.00074)]
            .iter()
            .cloned()
            .collect::<HashMap<_,_>>()
    };
}

fn hamming_distance(lhs: &[u8], rhs: &[u8]) -> usize {
    lhs.iter()
        .zip(rhs.iter())
        .map(|(a,b)| a^b)
        .map(|v| {
            let mut v = v;
            let mut count = 0usize;
            while v > 0 {
                count += (v % 2) as usize;
                v /= 2;
            }
            count})
        .sum()

}

fn read_input() -> Vec<u8> {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    let input_string = reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
        .join("");

    BASE64.decode(&to_bytes(&input_string)).unwrap()
}

fn to_bytes(input: &str) -> Vec<u8> {
    input.chars()
        .map(|c| c as u8)
        .collect()
}

fn hex_decode(input: &str) -> Vec<u8> {
    input.chars()
        .zip(input.chars().skip(1))
        .step_by(2)
        .map(|(c1,c2)| {
            let mut pair = String::with_capacity(2);
            pair.push(c1);
            pair.push(c2);
            pair})
        .map(|hex_byte_str| u8::from_str_radix(&hex_byte_str, 16).unwrap())
        .collect::<Vec<u8>>()
}

fn hex_encode(input: &Vec<u8>) -> String {
    input.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}


fn xor(input: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    input
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, key)| b^key)
        .collect()
}

fn xor_decode(input: &Vec<u8>, key: &Vec<u8>) -> String {
    xor(input, key).iter()
        .filter(|b| b.is_ascii())
        .map(|b| *b as char)
        .collect::<String>()
}

fn main() {
    let input = read_input();

    let x = to_bytes("this is a test");
    let y = to_bytes("wokka wokka!!!");
    println!("Result: {}", hamming_distance(x.as_slice(), y.as_slice()));

    //println!("Result:\n{:?}", input);
}
