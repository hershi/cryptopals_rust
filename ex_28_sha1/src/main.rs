use utils::sha1::*;

fn print_hash(hash: &[u32]) {
    print!("Hash : ");
    for w in hash {
        print!("{:08x}", w);
    }
    println!("");
}

fn main() {
    // Hash examples from wikipedia
    print_hash(&sha1(b"The quick brown fox jumps over the lazy dog"));
    print_hash(&sha1(b"The quick brown fox jumps over the lazy cog"));
    print_hash(&sha1(b""));
}
