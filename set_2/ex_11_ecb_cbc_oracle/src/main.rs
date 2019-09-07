use utils::*;
use utils::encryption::*;
use rand::prelude::*;

const KEY_SIZE : usize = 16;
const IV_SIZE : usize = 16;

fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let key = random_buffer(KEY_SIZE);

    let input = add_pre_post_fixes(input);

    let use_cbc = random();
    if use_cbc {
        println!("Using CBC");
        cbc_encrypt(&input, &key, random_buffer(IV_SIZE))
    } else {
        println!("Using ECB");
        ecb_encrypt(&input, &key)
    }
}

fn add_pre_post_fixes(input: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let prefix_size = rng.gen_range(5,11);
    let postfix_size = rng.gen_range(5,11);

    //println!("Prefix/Postfix sizes: {}/{}", prefix_size, postfix_size);
    let prefix = random_buffer(prefix_size);
    let postfix = random_buffer(postfix_size);
    prefix.iter()
        .chain(input)
        .chain(&postfix)
        .cloned()
        .collect()
}

fn main() {
    let input = "HELLO WORLD!!!!!!!!!!!!".as_bytes();
    for i in 0..20 {
        println!("{}: {:?}", i, encryption_oracle(&input));
    }
}

