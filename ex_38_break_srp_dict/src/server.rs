use bigint::*;
use hmac::*;
use rand::prelude::*;
use std::sync::mpsc::{Sender, Receiver};
use ::utils::diffie_hellman::*;
use super::utils::*;
use super::messages::*;

use super::{P,G};

pub fn server(to_client: Sender<String>, from_client: Receiver<String>) {
    println!("Server:Rregistering user");

    let user_record = gen_user_record(P, &G.to_biguint().unwrap());

    println!("Server: Waiting for ClientHello...");
    let client_hello = &from_client.recv().unwrap();
    let client_hello = ClientHello::deserialize(&client_hello);
    let client_public = biguint_from_string(&client_hello.public_key);

    let (server_private, server_public) = generate_private_public(
        &get_nist_prime(),
        &G.to_biguint().unwrap());

    let u = thread_rng().gen::<u128>();
    let challenge = ServerChallenge::new(
        user_record.salt.clone(),
        &server_public,
        u);
    to_client.send(challenge.serialize()).unwrap();

    let u = u.to_biguint().unwrap();
    let n = get_nist_prime();
    let s = (client_public * user_record.verifier.modpow(&u, &n))
        .modpow(&server_private, &n);

    println!("Server: Waiting for ClientResponse...");
    let client_response = &from_client.recv().unwrap();
    let client_response = ClientResponse::deserialize(&client_response);

    let ok = hmac_s(&s, user_record.salt)
        .verify(&client_response.resp).is_ok();

    println!("Server: Validation succeeded? {}; sending response", ok);
    let server_ok = ServerOk::new(ok);
    to_client.send(server_ok.serialize()).unwrap();
    println!("Server: Done");
}
