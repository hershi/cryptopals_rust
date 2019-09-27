const W: u32 = 32;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;

fn temper(y: u32) -> u32 {
    let y = y ^ ((y >> U) & D);
    let y = y ^ ((y << S) & B);
    let y = y ^ ((y << T) & C);
    let y = y ^ (y >> L);

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


fn untemper_helper(val: u32, shift: u32) -> u32 {
    let bitmask = (2u32.pow(W-shift)-1) << shift;
    let yh = val & bitmask;
    let yl = (val & !bitmask) ^ (yh >> shift);
    yh | yl
}

fn untemper(y: u32) -> u32 {
    let y = untemper_right_shift(y, L, 0xFFFFFFFF);
    let y = untemper_left_shift(y, T, C);
    let y = untemper_left_shift(y, S, B);
    let y = untemper_right_shift(y, U, D);
    y
}

fn main() {
    let y = 12354321u32;
    let tempered_y = temper(y);
    println!("temper({}) {}", y, tempered_y);
    let untempered = untemper(tempered_y);
    println!("val {:032b}", y);
    println!("untemper({}) {}", tempered_y, untempered);
}

