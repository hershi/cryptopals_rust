#[macro_use]
extern crate lazy_static;

use std::io::prelude::*;
use std::collections::HashMap;
use std::io::BufReader;
use std::fs::File;

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
fn read_input() -> Vec<String> {
    let input_file = File::open("src/4.txt").unwrap();
    let reader = BufReader::new(input_file);
    reader.lines()
        .map(|x|x.unwrap())
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

fn xor_decode(input: &Vec<u8>, key: u8) -> String {
    input
        .iter()
        .map(|b| b^key)
        .filter(|b| b.is_ascii())
        .map(|b| b as char)
        .collect::<String>()
}

fn get_char_frequencies(input: &str) -> HashMap<char, f32> {
    input
        .chars()
        .fold(
            HashMap::new(),
            |mut acc, c| { *acc.entry(c).or_insert(0f32) += 1f32; acc})
}

fn english_score(input: &str) -> f32 {
    let mut frequencies = get_char_frequencies(&input);

    let length = input.len() as f32;
    for (_, v) in frequencies.iter_mut() {
        *v = *v / length;
    }

    EXPECTED_FREQUENCIES.iter()
        .map(|(k,v)| {
            let freq = frequencies.get(&k).unwrap_or(&0f32);
            (v - freq).abs() })
        .sum()
}

// Find the best key to decode the input, and return
// the decoded string + its score
fn get_best_decoding(input: &str, consider_partial: bool) -> (&str, String, u64) {
    let input_bytes = hex_decode(&input);
    (0..255)
        .map(|i: u8| xor_decode(&input_bytes, i))
        .filter(|decoded| consider_partial || input_bytes.len() == decoded.len())
        .map(|decoded| {
            let score = english_score(&decoded);
            (input, decoded, (score * 1000f32) as u64) })
        .min_by_key(|(_, _, score)| score.clone())
        .unwrap()
}

fn main() {
    let input_lines = read_input();
    let result = input_lines.iter()
        .map(|input| get_best_decoding(&input, true))
        .min_by_key(|(_,_, score)| score.clone())
        .unwrap();

    println!(
        "Input: {}, Message: {}, Score: {}", result.0, result.1, result.2);
}
