#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

const w: u32 = 32;
const n: usize = 624;
const m: usize = 397;
const r: u32 = 31;
const a: u32 = 0x9908B0DF;
const u: u32 = 11;
const d: u32 = 0xFFFFFFFF;
const s: u32 = 7;
const b: u32 = 0x9D2C5680;
const t: u32 = 15;
const c: u32 = 0xEFC60000;
const l: u32 = 18;
const f: u64 = 1812433253;

const lowest_w_bitmask: u32 = ((1isize << w) - 1) as u32;
const lower_mask: u32 = ((1isize << r) - 1) as u32; // That is, the binary number of r 1's
const upper_mask: u32 = (!lower_mask as isize & ((1isize << w) - 1)) as u32;

pub struct MersenneTwister {
    state: [u32; n],
    index: usize,

}

impl MersenneTwister {
    // Initialize the generator from a seed
    pub fn new(seed: u32) -> MersenneTwister {
        let mut mt = MersenneTwister{ state: [0;n], index: n };
        mt.state[0] = seed;

        for i in 1..n {
            let tmp = lowest_w_bitmask as u64 &
                ((f * (mt.state[i-1] ^ (mt.state[i-1] >> (w-2))) as u64)
                + i as u64);
            mt.state[i] = tmp as u32;
        }
        mt
    }

    // Extract a tempered value based on MT[index]
    // calling twist() every n numbers
    pub fn extract_number(&mut self) -> u32 {
        if self.index > n {
            panic!("Generator was never seeded");
        }

        if self.index == n {
            self.twist();
        }

        let y = self.state[self.index];
        let y = y ^ ((y >> u) & d);
        let y = y ^ ((y << s) & b);
        let y = y ^ ((y << t) & c);
        let y = y ^ (y >> l);

        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..n {
            let x = (self.state[i] & upper_mask)
                + (self.state[(i+1) % n] & lower_mask);
            let xA = x >> 1;

            let xA = if x % 2 == 0 { xA } else { xA ^ a };
            self.state[i] = self.state[(i + m) % n] ^ xA;
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
}
