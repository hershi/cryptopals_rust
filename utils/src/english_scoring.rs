use std::collections::HashMap;

lazy_static! {
    pub static ref EXPECTED_FREQUENCIES: HashMap<char, f32> = {
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

pub fn get_char_frequencies(input: &str) -> HashMap<char, f32> {
    input
        .chars()
        .fold(
            HashMap::new(),
            |mut acc, c| { *acc.entry(c).or_insert(0f32) += 1f32; acc})
}

pub fn get_byte_frequencies(input: &[u8]) -> HashMap<u8, f32> {
    input
        .iter()
        .fold(
            HashMap::new(),
            |mut acc, b| { *acc.entry(*b).or_insert(0f32) += 1f32; acc})
}


pub fn english_score(input: &str) -> f32 {
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
