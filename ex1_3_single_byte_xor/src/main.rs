use std::collections::HashMap;

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

fn decode_with(input: &Vec<u8>, key: u8) -> String {
    input
        .iter()
        .map(|b| b^key)
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b as char)
        .collect::<String>()
}

fn english_score(input: &str) -> f32 {
    let expected_frequency_distribution =
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
        .collect::<HashMap<_,_>>();

    let mut frequencies =
        input
        .chars()
        .fold(HashMap::new(), |mut acc, c| { *acc.entry(c).or_insert(0f32) += 1f32; acc});

    let length = input.len() as f32;
    for (_, v) in frequencies.iter_mut() {
        *v = *v / length;
    }

    expected_frequency_distribution.iter()
        .map(|(k,v)| {
            let freq = frequencies.get(&k).unwrap_or(&0f32);
            (v - freq).abs() })
        .sum()
}

fn main() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let input_bytes = hex_decode(&input);


    let decoded = decode_with(&input_bytes, 0);
    let score = english_score(&decoded);
    println!("{}: {}", decoded, score);

    let result = (0..255)
        .map(|i: u8| {
            let decoded = decode_with(&input_bytes, i);
            let score = english_score(&decoded);
            (i, decoded, score) })
        .min_by_key(|(_, _, score)| (score * 1000f32) as u64)
        .unwrap();

    println!("Key: {}, Message: {}", result.0, result.1);
}
