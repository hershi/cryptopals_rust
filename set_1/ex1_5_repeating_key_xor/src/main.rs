use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;

fn read_input() -> String {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
        .join("\n")
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
    let key = to_bytes("ICE");

    let bytes = to_bytes(&input);
    let bytes = xor(&bytes, &key);
    let result = hex_encode(&bytes);

    println!("Result:\n{}", result);
}
