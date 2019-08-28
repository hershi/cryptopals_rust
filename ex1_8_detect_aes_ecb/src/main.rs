use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::collections::HashMap;

fn read_input() -> Vec<Vec<u8>> {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    reader.lines()
        .map(|line|line.unwrap())
        .map(|line|hex_decode(&line))
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

fn process(input: &[u8]) -> HashMap<&[u8], usize> {
    let block_size = 16;
    let mut freq = HashMap::new();

    for i in 0..(input.len()/block_size) {
        *freq.entry(&input[block_size * i..block_size * (i + 1)]).or_insert(0) += 1
    }

    freq
}

fn main() {
    let input = read_input();
    for (i, line) in input.iter().enumerate() {
        let result = process(&line);
        if result.values().all(|v| *v <= 1) { continue; }
        println!("Result: Line {}\n{}\n", i, hex_encode(&line));
    }
}
