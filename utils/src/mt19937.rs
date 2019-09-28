#![allow(non_snake_case)]

const W: u32 = 32;
const N: usize = 624;
const M: usize = 397;
const R: u32 = 31;
const A: u32 = 0x9908B0DF;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;
const F: u64 = 1812433253;

const LOWEST_W_BITMASK: u32 = ((1isize << W) - 1) as u32;
const LOWER_MASK: u32 = ((1isize << R) - 1) as u32; // That is, the binary number of r 1's
const UPPER_MASK: u32 = (!LOWER_MASK as isize & ((1isize << W) - 1)) as u32;

pub struct MersenneTwister {
    pub state: [u32; N],
    pub index: usize,

}

impl MersenneTwister {
    // Initialize the generator from a seed
    pub fn new(seed: u32) -> MersenneTwister {
        let mut mt = MersenneTwister{ state: [0;N], index: N };
        mt.state[0] = seed;

        for i in 1..N {
            let tmp = LOWEST_W_BITMASK as u64 &
                ((F * (mt.state[i-1] ^ (mt.state[i-1] >> (W-2))) as u64)
                + i as u64);
            mt.state[i] = tmp as u32;
        }
        mt
    }

    // Extract a tempered value based on MT[index]
    // calling twist() every n numbers
    pub fn extract_number(&mut self) -> u32 {
        if self.index > N {
            panic!("Generator was never seeded");
        }

        if self.index == N {
            self.twist();
        }

        let y = self.state[self.index];
        let y = y ^ ((y >> U) & D);
        let y = y ^ ((y << S) & B);
        let y = y ^ ((y << T) & C);
        let y = y ^ (y >> L);

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..N {
            let x = (self.state[i] & UPPER_MASK)
                + (self.state[(i+1) % N] & LOWER_MASK);
            let xA = x >> 1;

            let xA = if x % 2 == 0 { xA } else { xA ^ A };
            self.state[i] = self.state[(i + M) % N] ^ xA;
        }

        self.index = 0;
    }

    pub fn print(&self) {
        print!("state: [");
        for x in self.state.iter() {
            print!("{}, ", x);
        }
        println!("]");
        println!("Index: {}", self.index);
    }

    pub fn untemper(y: u32) -> u32 {
        let y = MersenneTwister::untemper_right_shift(y, L, 0xFFFFFFFF);
        let y = MersenneTwister::untemper_left_shift(y, T, C);
        let y = MersenneTwister::untemper_left_shift(y, S, B);
        let y = MersenneTwister::untemper_right_shift(y, U, D);
        y
    }

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
}
