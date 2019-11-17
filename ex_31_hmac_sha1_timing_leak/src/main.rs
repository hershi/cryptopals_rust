use utils::hmac::*;

fn main() {
    println!("hmac_sha1('key', 'abc'): {:?}", hmac_sha1(b"key", b"abc"));
}
