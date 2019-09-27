use rand::prelude::*;
use utils::mt19937::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn guess_seed(current_time: u64, first_rand: u32) -> Option<u64> {
    (current_time-2000..current_time)
        .map(|t| (t, MersenneTwister::new(t as u32).extract_number()))
        .find_map(|(t, r)| if r == first_rand { Some(t) } else { None })
}

fn main() {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut rng = thread_rng();
    let wait1 = rng.gen_range(40, 1000);
    let wait2 = rng.gen_range(40, 1000);

    let seed = timestamp + wait1;

    println!("seed: {}", seed);
    let mut mt = MersenneTwister::new(seed as u32);
    let first_rand = mt.extract_number();

    let current_time = timestamp + wait1 + wait2;
    println!("current_time: {}; first rand: {}\n", current_time, first_rand);

    let guessed_seed = guess_seed(current_time, first_rand);
    println!("Guessed seed:real seed {:?}:{}, match? {} ",
             guessed_seed,
             seed,
             guessed_seed == Some(seed));
}
