#[macro_use]
extern crate lazy_static;

use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::collections::HashMap;
use data_encoding::BASE64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_smoke_test() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);
    }

    #[test]
    fn normalized_hamming_distance_smoke_test() {
        assert_eq!(normalized_hamming_distance(b"this is a test", b"wokka wokka!!!"), 37f32 / 14f32);
    }
}

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
    assert!(lhs.len() == rhs.len());
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

fn normalized_hamming_distance(lhs: &[u8], rhs: &[u8]) -> f32 {
    hamming_distance(lhs, rhs) as f32 / lhs.len() as f32
}

fn read_input() -> Vec<u8> {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    let input_string = reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
        .join("");

    BASE64.decode(input_string.as_bytes()).unwrap()
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
fn get_best_decoding(bytes: &Vec<u8>, consider_partial: bool) -> (String, u8, u64) {
    (0..255)
        .map(|i| (xor_decode(&bytes, &vec![i]), i))
        .filter(|(decoded, _)| consider_partial || bytes.len() <= decoded.len() + 2)
        .map(|(decoded, key)| {
            let score = english_score(&decoded);
            (decoded, key, (score * 1000f32) as u64) })
        .min_by_key(|( _, _, score)| score.clone())
        .unwrap()
}

fn evaluate_keysize(size: usize, input: &[u8]) -> f32 {
    if input.len() < size * 2 { return std::f32::MAX; }

    let mut count = 0f32;
    let mut score = 0f32;
    for i in 0..4 {
        if size * (i+3) > input.len() { continue; }
        count += 1f32;
        score += normalized_hamming_distance(
            &input[i * size..(i+1)*size],
            &input[(i+2) * size..(i+3)*size]);
    }

    score / count
}

// Return a sorted vector of keysizes and their score
fn get_likely_keysizes(input: &[u8]) -> Vec<(usize, f32)> {
    let mut result = (2..40)
        .map(|keysize| (keysize, evaluate_keysize(keysize, &input)))
        .collect::<Vec<(usize, f32)>>();

    result.sort_by_key(|&(_, score)| (score * 10000f32) as usize);

    result
}

fn find_key(input: &Vec<u8>, key_size: usize) -> Vec<u8> {
    (0..key_size)
        .map(|i|
             input
                .iter()
                .skip(i)
                .step_by(key_size)
                .map(|x| *x)
                .collect::<Vec<u8>>())
        .map(|bytes| get_best_decoding(&bytes, false))
        .map(|(_,key,_)| key)
        .collect()
}

fn main() {
    let input = read_input();
    let key_sizes = get_likely_keysizes(&input);

    //println!("{:?}", key_sizes);
    for (i,_) in key_sizes.iter().take(1) {
        let key = find_key(&input, *i);
        println!("Key size: {}", i);
        println!("Message: {}", xor_decode(&input, &key));
    }
}
