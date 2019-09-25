use super::*;
use super::english_scoring::*;

pub fn is_valid_decode(input: &[u8]) -> bool {
    let punctuation = b":;?!\"/#$%&'*.,-".to_vec();
    input.iter().all(
        |b| b.is_ascii_alphanumeric()
            || b.is_ascii_whitespace()
            //|| b.is_ascii_punctuation())
            || punctuation.contains(b))
}

// Find the best key to decode the input, and return
// the decoded string + its score
pub fn get_best_decoding(bytes: &Vec<u8>) -> (Vec<u8>, u8, u64) {
    (0..255)
        .map(|i| (xor(&bytes, &vec![i]), i))
        .filter(|(decoded,_)| is_valid_decode(decoded))
        .map(|(decoded, key)| {
            let score = english_score(&decoded);
            (decoded, key, (score * 1000f32) as u64) })
        .min_by_key(|( _, _, score)| score.clone())
        .unwrap()
}

pub fn find_xor_key(input: &Vec<u8>, key_size: usize) -> Vec<u8> {
    (0..key_size)
        .map(|i|
             input
                .iter()
                .skip(i)
                .step_by(key_size)
                .map(|x| *x)
                .collect::<Vec<u8>>())
        .map(|bytes| get_best_decoding(&bytes))
        .map(|(_,key,_)| key)
        .collect()
}
