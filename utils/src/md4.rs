use std::num::Wrapping;
use super::hash_utils::*;

pub fn pad(mut message: Vec<u8>) -> Vec<u8> {
    // Message length in bits
    let message_len : u64 = message.len() as u64 * 8;
    let message_len_with_size = message_len + MESSAGE_LEN_BITS;

    // Note that if the original message + length field are exactly at the block
    // boundary we'll get `bits_in_last_block == 0` and as a result
    // `padding_needed == <block size>`.
    // This is intended, since we need to account for the extra 1-bit that
    // is always appended for padding
    let bits_in_last_block = message_len_with_size % BLOCK_SIZE_IN_BITS;
    let padding_needed = BLOCK_SIZE_IN_BITS - bits_in_last_block;

    // We're dealing with messages made of bytes, so padding
    // should always be byte aligned
    assert!(padding_needed % 8 == 0);

    if padding_needed > 0 {
        let num_zero_padding_bytes = padding_needed as usize / 8 - 1;
        message.push(0x80);
        message.resize(message.len() + num_zero_padding_bytes, 0);
    }

    message.extend_from_slice(&message_len.to_le_bytes());
    message
}

#[derive(Clone, Debug)]
pub struct Md4State {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

pub fn md4_continuation(message: Vec<u8>, state: Md4State) -> Vec<u8> {
    let mut s = state.clone();
    let block_size_in_bytes = (BLOCK_SIZE_IN_BITS / 8) as usize;
    message.chunks(block_size_in_bytes)
        .for_each(|block| s = process_block(block, &s));

    s.a.to_le_bytes().iter()
        .chain(s.b.to_le_bytes().iter())
        .chain(s.c.to_le_bytes().iter())
        .chain(s.d.to_le_bytes().iter())
        .cloned()
        .collect()
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

// See https://tools.ietf.org/html/rfc1320#section-3.3
pub fn md4(message: &[u8]) -> Vec<u8> {
    let message = pad(message.to_vec());
    let state = Md4State{
        a: 0x67452301,
        b: 0xEFCDAB89,
        c: 0x98BADCFE,
        d: 0x10325476,
    };

    md4_continuation(message, state)
}

fn r1(a: &mut u32, b: u32, c:u32, d:u32, xk: u32, s: u8) {
    *a = circular_shift(
        (Wrapping(*a) +
        Wrapping(f(b,c,d)) +
        Wrapping(xk as u32)).0, s);
}

fn r2(a: &mut u32, b: u32, c:u32, d:u32, xk: u32, s: u8) {
    *a = circular_shift(
        (Wrapping(*a) +
        Wrapping(g(b,c,d)) +
        Wrapping(xk as u32) +
        Wrapping(0x5A827999)).0, s);
}

fn r3(a: &mut u32, b: u32, c:u32, d:u32, xk: u32, s: u8) {
    *a = circular_shift(
        (Wrapping(*a) +
        Wrapping(h(b,c,d)) +
        Wrapping(xk as u32) +
        Wrapping(0x6ED9EBA1)).0, s);
}

// https://tools.ietf.org/html/rfc1320#section-3.4
fn process_block(block: &[u8], state: &Md4State) -> Md4State{
    let words = block
        .chunks(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect::<Vec<u32>>();

    let mut s = state.clone();

    r1(&mut s.a, s.b, s.c, s.d, words[0], 3);
    r1(&mut s.d, s.a, s.b, s.c, words[1], 7);
    r1(&mut s.c, s.d, s.a, s.b, words[2], 11);
    r1(&mut s.b, s.c, s.d, s.a, words[3], 19);
    r1(&mut s.a, s.b, s.c, s.d, words[4], 3);
    r1(&mut s.d, s.a, s.b, s.c, words[5], 7);
    r1(&mut s.c, s.d, s.a, s.b, words[6], 11);
    r1(&mut s.b, s.c, s.d, s.a, words[7], 19);
    r1(&mut s.a, s.b, s.c, s.d, words[8], 3);
    r1(&mut s.d, s.a, s.b, s.c, words[9], 7);
    r1(&mut s.c, s.d, s.a, s.b, words[10], 11);
    r1(&mut s.b, s.c, s.d, s.a, words[11], 19);
    r1(&mut s.a, s.b, s.c, s.d, words[12], 3);
    r1(&mut s.d, s.a, s.b, s.c, words[13], 7);
    r1(&mut s.c, s.d, s.a, s.b, words[14], 11);
    r1(&mut s.b, s.c, s.d, s.a, words[15], 19);

    r2(&mut s.a, s.b, s.c, s.d, words[0], 3);
    r2(&mut s.d, s.a, s.b, s.c, words[4], 5);
    r2(&mut s.c, s.d, s.a, s.b, words[8], 9);
    r2(&mut s.b, s.c, s.d, s.a, words[12], 13);
    r2(&mut s.a, s.b, s.c, s.d, words[1], 3);
    r2(&mut s.d, s.a, s.b, s.c, words[5], 5);
    r2(&mut s.c, s.d, s.a, s.b, words[9], 9);
    r2(&mut s.b, s.c, s.d, s.a, words[13], 13);
    r2(&mut s.a, s.b, s.c, s.d, words[2], 3);
    r2(&mut s.d, s.a, s.b, s.c, words[6], 5);
    r2(&mut s.c, s.d, s.a, s.b, words[10], 9);
    r2(&mut s.b, s.c, s.d, s.a, words[14], 13);
    r2(&mut s.a, s.b, s.c, s.d, words[3], 3);
    r2(&mut s.d, s.a, s.b, s.c, words[7], 5);
    r2(&mut s.c, s.d, s.a, s.b, words[11], 9);
    r2(&mut s.b, s.c, s.d, s.a, words[15], 13);

    r3(&mut s.a, s.b, s.c, s.d, words[0], 3);
    r3(&mut s.d, s.a, s.b, s.c, words[8], 9);
    r3(&mut s.c, s.d, s.a, s.b, words[4], 11);
    r3(&mut s.b, s.c, s.d, s.a, words[12], 15);
    r3(&mut s.a, s.b, s.c, s.d, words[2], 3);
    r3(&mut s.d, s.a, s.b, s.c, words[10], 9);
    r3(&mut s.c, s.d, s.a, s.b, words[6], 11);
    r3(&mut s.b, s.c, s.d, s.a, words[14], 15);
    r3(&mut s.a, s.b, s.c, s.d, words[1], 3);
    r3(&mut s.d, s.a, s.b, s.c, words[9], 9);
    r3(&mut s.c, s.d, s.a, s.b, words[5], 11);
    r3(&mut s.b, s.c, s.d, s.a, words[13], 15);
    r3(&mut s.a, s.b, s.c, s.d, words[3], 3);
    r3(&mut s.d, s.a, s.b, s.c, words[11], 9);
    r3(&mut s.c, s.d, s.a, s.b, words[7], 11);
    r3(&mut s.b, s.c, s.d, s.a, words[15], 15);

    Md4State{
        a: (Wrapping(state.a) + Wrapping(s.a)).0,
        b: (Wrapping(state.b) + Wrapping(s.b)).0,
        c: (Wrapping(state.c) + Wrapping(s.c)).0,
        d: (Wrapping(state.d) + Wrapping(s.d)).0,
    }
}

