use utils::md4::*;

pub fn print_hash(hash: &[u8]) {
    print!("Hash : ");
    for b in hash {
        print!("{:02x}", b);
    }
    println!("");
}

fn main() {
    let strings = vec![
        b"".to_vec(),
        b"a".to_vec(),
        b"abc".to_vec(),
        b"message digest".to_vec(),
        ];
    for s in strings {
        print!("Message '{}' ", String::from_utf8(s.clone()).unwrap());
        print_hash(&md4(&s));
    }
}
