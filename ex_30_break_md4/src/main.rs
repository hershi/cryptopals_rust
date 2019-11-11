use utils::md4::*;

pub fn print_hash(hash: &[u8]) {
    print!("Hash : ");
    for b in hash {
        print!("{:02x}", b);
    }
    println!("");
}

fn main() {
    print_hash(&md4(b""));
    print_hash(&md4(b"a"));
    //print_hash(&md4(b"abc"));
}
