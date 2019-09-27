use utils::mt19937::*;

fn main() {
    let mut mt = MersenneTwister::new(0u32);

    for _ in 1..10 {
        println!("{}", mt.extract_number());
    }
}
