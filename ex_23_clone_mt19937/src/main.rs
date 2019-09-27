const W: u32 = 32;
const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;

fn temper(y: u32) -> u32 {
    //let y = y ^ ((y >> U) & D);
    //let y = y ^ ((y << S) & B);
    let y = y ^ ((y << T) & C);
    //let y = y ^ (y >> L);

    y
}

fn untemper_helper1(val: u32, shift: u32, mask: u32) -> u32 {
    let bitmask = 2u32.pow(shift)-1;
    let yl = val & bitmask;
    let yh = (val & (bitmask << shift)) ^ ((yl << shift) & mask);
    let yhh = (val & (bitmask << (shift *2))) ^ ((yl << (shift *2)) & mask);
    println!("yl  {:032b}", yl);
    println!("yh  {:032b}", yh);
    println!("yhh {:032b}", yhh);
    println!("cmb {:032b}", yhh | yh | yl);

    yhh | yh | yl
}


fn untemper_helper(val: u32, shift: u32) -> u32 {
    let bitmask = (2u32.pow(W-shift)-1) << shift;
    let yh = val & bitmask;
    let yl = (val & !bitmask) ^ (yh >> shift);
    yh | yl
}

fn untemper(y: u32) -> u32 {
    //let y = self.state[self.index];
    //let y = y ^ ((y >> U) & D);
    //let y = y ^ ((y << S) & B);
    //let y = y ^ ((y << T) & C);
    untemper_helper1(y, T, C)
}

fn main() {
    let y = 12354321u32;
    let tempered_y = temper(y);
    println!("temper({}) {}", y, tempered_y);
    let untempered = untemper(tempered_y);
    println!("val {:032b}", y);
    println!("untemper({}) {}", tempered_y, untempered);
}
