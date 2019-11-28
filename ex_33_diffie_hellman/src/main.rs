extern crate rand;
extern crate num_bigint as bigint;

use bigint::{BigInt, ToBigInt};
use utils::diffie_hellman::*;

fn generate_session(p: &BigInt, g: &BigInt) {
    let (priv_a, pub_a) = generate_private_public(&p, &g);
    let (priv_b, pub_b) = generate_private_public(&p, &g);

    println!("a: {:X},\nA: {:X}\n", priv_a, pub_a);
    println!("b: {:X},\nB: {:X}\n", priv_b, pub_b);

    let s_a = derive_session_key(&p, &priv_a, &pub_b);
    let s_b = derive_session_key(&p, &priv_b, &pub_a);

    println!("sA: {}\nsB: {}\n\nsA==sB? {}", s_a, s_b, s_a == s_b);
}

fn main() {
    generate_session(
        &37.to_bigint().unwrap(),
        &5.to_bigint().unwrap());

    println!("");

    let (p,g) = generate_pg();
    generate_session(&p,&g);
}
