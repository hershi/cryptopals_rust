#[macro_use]
extern crate lazy_static;

use rand::prelude::*;
use utils::*;
use utils::encoding::*;
use utils::hash_utils::*;
use utils::sha1::*;

const MESSAGE : &[u8] = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
const SUFFIX : &[u8] = b";admin=true";
const MAX_KEY_SIZE : usize = 10;

lazy_static! {
    pub static ref KEY_SIZE : usize = {
        let mut rng = thread_rng();
        rng.gen_range(1,MAX_KEY_SIZE)
    };
    pub static ref KEY: Vec<u8> = random_buffer(*KEY_SIZE);
}

fn secret_prefix_mac(message: &[u8]) -> Vec<u32> {
    let prefixed_message =
        KEY.iter().chain(message.iter())
        .cloned()
        .collect::<Vec<u8>>();

    sha1(&prefixed_message)
}

fn break_mac_to_state(mac: &Vec<u32>) -> Sha1State {
    Sha1State{
        h0: mac[0],
        h1: mac[1],
        h2: mac[2],
        h3: mac[3],
        h4: mac[4],
    }
}

fn verify(message: &[u8], mac: &Vec<u32>) -> bool {
    secret_prefix_mac(message) == *mac
}

fn pad_with_size(message: &[u8], key_size: usize) -> Vec<u8> {
    pad(std::iter::repeat(&0u8)
        .take(key_size)
        .chain(message.iter())
        .cloned()
        .collect::<Vec<u8>>())
}

fn main() {
    println!("key size: {}", *KEY_SIZE);
    //println!("key: {:?}", key);
    println!("Message: {:?}", to_string(MESSAGE));
    let mac = secret_prefix_mac(&MESSAGE);
    print_hash(&mac);

    let state = break_mac_to_state(&mac);
    for key_size in 1..MAX_KEY_SIZE {
        // Generate (dummy_key || original_message || glue_padding)
        let mut forged_message = pad_with_size(&MESSAGE, key_size);

        // Remember the resulting length, since we'll only want to pass
        // the bytes beyond that point to the continuation
        let original_message_len_with_padding = forged_message.len();

        // Generate (dummy_key || original_message || glue_padding || new_message)
        forged_message.extend_from_slice(SUFFIX);

        // Generate (dummy_key || original_message || glue_padding || new_message || padding)
        let padded_forged_message = pad(forged_message.clone());


        // Get only the (new_message || padding) part to pass to the continuation
        let continuation_content = padded_forged_message.iter()
            .skip(original_message_len_with_padding)
            .cloned()
            .collect::<Vec<u8>>();

        let forged_mac = sha1_continuation(continuation_content, state.clone());

        // Remove the dummy key from the forged_message before verification
        let for_verification = forged_message.split_off(key_size);
        if verify(&for_verification, &forged_mac) {
            println!("Forged successfully. Key size is {}", key_size);
            return;
        }
    }

    println!("Couldn't forge!");
}
