extern crate rand;
extern crate num_bigint as bigint;

use bigint::{BigInt, ToBigInt, RandBigInt};

fn gen_private_public(p: &BigInt, g: &BigInt) -> (bigint::BigInt, bigint::BigInt) {
    let mut rng = rand::thread_rng();
    let private = rng.gen_bigint_range(&0.to_bigint().unwrap(), p);
    let public = g.modpow(&private, p);
    (private.clone(), public.clone())
}

fn generate_session(p: &BigInt, g: &BigInt) {
    let (priv_a, pub_a) = gen_private_public(&p, &g);
    let (priv_b, pub_b) = gen_private_public(&p, &g);

    println!("a: {:X},\nA: {:X}\n", priv_a, pub_a);
    println!("b: {:X},\nB: {:X}\n", priv_b, pub_b);

    let s_a = pub_b.modpow(&priv_a, &p);
    let s_b = pub_a.modpow(&priv_b, &p);

    println!("sA: {}\nsB: {}\n\nsA==sB? {}", s_a, s_b, s_a == s_b);
}

fn main() {
    generate_session(
        &37.to_bigint().unwrap(),
        &5.to_bigint().unwrap());

    println!("");

    generate_session(
        &BigInt::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 32).unwrap(),
        &2.to_bigint().unwrap());
}
