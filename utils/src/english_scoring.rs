use std::collections::HashMap;

lazy_static! {
    pub static ref EXPECTED_FREQUENCIES: HashMap<u8, f32> = {
        [(b'a', 0.08167),
        (b'b', 0.01492),
        (b'c', 0.02782),
        (b'd', 0.04253),
        (b'e', 0.12702),
        (b'f', 0.02228),
        (b'g', 0.02015),
        (b'h', 0.06094),
        (b'i', 0.06966),
        (b'j', 0.00153),
        (b'k', 0.00772),
        (b'l', 0.04025),
        (b'm', 0.02406),
        (b'n', 0.06749),
        (b'o', 0.07507),
        (b'p', 0.01929),
        (b'q', 0.00095),
        (b'r', 0.05987),
        (b's', 0.06327),
        (b't', 0.09056),
        (b'u', 0.02758),
        (b'v', 0.00978),
        (b'w', 0.02360),
        (b'x', 0.00150),
        (b'y', 0.01974),
        (b'z', 0.00074)]
            .iter()
            .cloned()
            .collect::<HashMap<_,_>>()
    };
}

pub fn get_char_frequencies(input: &[u8]) -> HashMap<u8, f32> {
    input.iter()
        .fold(
            HashMap::new(),
            |mut acc, c| { *acc.entry(*c).or_insert(0f32) += 1f32; acc})
}

pub fn get_byte_frequencies(input: &[u8]) -> HashMap<u8, f32> {
    input
        .iter()
        .fold(
            HashMap::new(),
            |mut acc, b| { *acc.entry(*b).or_insert(0f32) += 1f32; acc})
}


pub fn english_score(input: &[u8]) -> f32 {
    let mut frequencies = get_char_frequencies(input);

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

