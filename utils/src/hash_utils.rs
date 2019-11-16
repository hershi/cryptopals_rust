pub const MESSAGE_LEN_BITS: u64 = 64;
pub const BLOCK_SIZE_IN_BITS : u64 = 512;

pub fn circular_shift(word: u32, shift: u8) -> u32 {
    (word << shift) | (word >> (32 -shift))
}

pub fn print_hash(hash: &[u32]) {
    print!("Hash : ");
    for w in hash {
        print!("{:08x}", w);
    }
    println!("");
}

