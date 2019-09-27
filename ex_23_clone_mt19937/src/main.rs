use utils::mt19937::*;

const N: usize = 624;
const W: u32 = 32;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;

fn untemper_right_shift(val: u32, shift: u32, mask: u32) -> u32 {
    let mut base_bitmask = 2u64.pow(shift)-1 << ((W / shift) * shift);
    let mut bits_handled = 0;

    let mut acc = 0;
    while bits_handled < W {
        let bitmask = base_bitmask as u32;
        let x = (val & bitmask) ^ (((acc >> shift) & mask) & bitmask);
        acc ^= x;

        bits_handled += shift;
        base_bitmask = base_bitmask >> shift;
    }
    acc
}

fn untemper_left_shift(val: u32, shift: u32, mask: u32) -> u32 {
    let mut bitmask = 2u32.pow(shift)-1;
    let mut bits_handled = 0;

    let mut acc = 0;
    while bits_handled < W {
        let x = (val & bitmask) ^(((acc << shift) & mask) & bitmask);
        acc ^= x;

        bits_handled += shift;
        bitmask = bitmask << shift;
    }
    acc
}

fn untemper(y: u32) -> u32 {
    let y = untemper_right_shift(y, L, 0xFFFFFFFF);
    let y = untemper_left_shift(y, T, C);
    let y = untemper_left_shift(y, S, B);
    let y = untemper_right_shift(y, U, D);
    y
}

fn main() {
    let mut mt = MersenneTwister::new(rand::random::<u32>());

    let mut state = Vec::with_capacity(N);
    for _ in 0..N {
        state.push(untemper(mt.extract_number()));
    }
    let next = mt.extract_number();
    println!("next: {:?}", next);

    let mut mt_state = [0; N];
    for i in 0..N {
        mt_state[i] = state[i];
    }

    let mut mt = MersenneTwister{state: mt_state, index:624};
    let reconstruction = mt.extract_number();
    println!("next reconstruction: {} (original: {}); same? {}",
        reconstruction,
        next,
        next == reconstruction);
}

