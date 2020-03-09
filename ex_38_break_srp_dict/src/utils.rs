extern crate num_bigint as bigint;
extern crate hmac;

use ::utils::diffie_hellman::*;
use bigint::*;
use hmac::*;
use rand::prelude::*;
use sha2::*;
use super::messages::*;

type HmacSha256 = Hmac<Sha256>;

pub fn gen_user_record_with_salt(salt: i32, p: &[u8], g: &BigUint) -> UserRecord {
    let x = gen_sha256_int(vec![&salt.to_le_bytes(), p]);
    let v = g.modpow(&x, &get_nist_prime());

    UserRecord{
        salt,
        verifier: v,
    }
}

pub fn gen_user_record(p: &[u8], g: &BigUint) -> UserRecord {
    gen_user_record_with_salt(thread_rng().gen::<i32>(), p, g)
}

pub fn calculate_client_proof(
        server_challenge: &str,
        password: &str,
        client_private: &BigUint) -> ClientResponse {
    let server_challenge = ServerChallenge::deserialize(server_challenge);
    let server_public = biguint_from_string(&server_challenge.public_key);
    let salt = server_challenge.salt;
    let u = server_challenge.u.to_biguint().unwrap();

    let x = gen_sha256_int(vec![&salt.to_le_bytes(), password.as_bytes()]);
    let s = server_public.modpow(&(client_private + u*x), &get_nist_prime());

    let hmac = hmac_s(&s, salt);

    ClientResponse::new(hmac.result().code().to_vec())
}

pub fn hmac_s(s: &BigUint, salt: i32) -> HmacSha256 {
    let k = Sha256::new()
        .chain(s.to_bytes_le())
        .result();

    let mut hmac = HmacSha256::new_varkey(&salt.to_le_bytes()).unwrap();
    hmac.input(&k);
    hmac
}

pub fn gen_sha256_int(inputs: Vec<&[u8]>) -> BigUint {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.input(input);
    }

    let x_h = hasher.result();
    BigUint::from_bytes_le(x_h.as_slice())
}

