use std::num::Wrapping;

const BLOCK_SIZE_IN_BITS : u64 = 512;
const MESSAGE_LEN_BITS: u64 = 64;

fn circular_shift(word: u32, shift: u8) -> u32 {
    (word << shift) | (word >> (32 -shift))
}

fn pad(mut message: Vec<u8>) -> Vec<u8> {
    // Message length in bits
    let message_len : u64 = message.len() as u64 * 8;
    let message_len_with_footer = message_len + MESSAGE_LEN_BITS;

    // Note that if the original message + length field are exactly at the block
    // boundary we'll get `bits_in_last_block == 0` and as a result
    // `padding_needed == <block size>`.
    // This is intended, since we need to account for the extra 1-bit that
    // is always appended for padding
    let bits_in_last_block = message_len_with_footer % BLOCK_SIZE_IN_BITS;
    let padding_needed = BLOCK_SIZE_IN_BITS - bits_in_last_block;

    // We're dealing with messages made of bytes, so padding
    // should always be byte aligned
    assert!(padding_needed % 8 == 0);

    if padding_needed > 0 {
        let num_zero_padding_bytes = padding_needed as usize / 8 - 1;
        message.push(0x80);
        message.resize(message.len() + num_zero_padding_bytes, 0);
    }

    message.extend_from_slice(&message_len.to_be_bytes());
    message
}

// See https://tools.ietf.org/html/rfc3174#section-5
fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => (b & c) | ((!b) & d),
        20..=39 => b ^ c ^ d,
        40..=59 => (b & c) | (b & d) | (c & d),
        60..=79 => b ^ c ^ d,
        _ => panic!("t out of range"),
    }
}

// See https://tools.ietf.org/html/rfc3174#section-5
fn k(t: usize) -> u32 {
    match t {
        0..=19 => 0x5A827999,
        20..=39 => 0x6ED9EBA1,
        40..=59 => 0x8F1BBCDC,
        60..=79 => 0xCA62C1D6,
        _ => panic!("t out of range"),
    }
}

#[derive(Clone)]
struct Sha1State {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

// See https://tools.ietf.org/html/rfc3174#section-6.1
pub fn sha1(message: &[u8]) -> Vec<u32> {
    let message = pad(message.to_vec());
    let mut state = Sha1State{
        h0: 0x67452301,
        h1: 0xEFCDAB89,
        h2: 0x98BADCFE,
        h3: 0x10325476,
        h4: 0xC3D2E1F0,
    };

    let block_size_in_bytes = (BLOCK_SIZE_IN_BITS / 8) as usize;
    message.chunks(block_size_in_bytes)
        .for_each(|block| state = process_block(block, &state));

    vec![state.h0, state.h1, state.h2, state.h3, state.h4]
}

// See https://tools.ietf.org/html/rfc3174#section-6.1
fn process_block(block: &[u8], state: &Sha1State) -> Sha1State{
    // 6.1.a
    let mut w = block.chunks(4)
        .map(|chunk| {
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) })
        .collect::<Vec<u32>>();

    assert!(w.len() == 16);
    w.reserve(64); // we're going to add 64 more elements

    // 6.1.b
    for t in 16..=79 {
        w.push(circular_shift(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1));
    }

    // 6.1.c
    let mut a = state.h0;
    let mut b = state.h1;
    let mut c = state.h2;
    let mut d = state.h3;
    let mut e = state.h4;

    // 6.1.d
    for t in 0..=79usize {
        let temp =
            Wrapping(circular_shift(a, 5)) +
            Wrapping(f(t,b,c,d)) +
            Wrapping(e) +
            Wrapping(w[t]) +
            Wrapping(k(t));
        e = d;
        d = c;
        c = circular_shift(b, 30);
        b = a;
        a = temp.0;
    }

    // 6.1.e
    Sha1State{
        h0: (Wrapping(state.h0) + Wrapping(a)).0,
        h1: (Wrapping(state.h1) + Wrapping(b)).0,
        h2: (Wrapping(state.h2) + Wrapping(c)).0,
        h3: (Wrapping(state.h3) + Wrapping(d)).0,
        h4: (Wrapping(state.h4) + Wrapping(e)).0,
    }
}
