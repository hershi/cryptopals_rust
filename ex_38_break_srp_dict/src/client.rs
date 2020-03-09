use bigint::*;
use hmac::*;
use std::sync::mpsc::{Sender, Receiver};
use ::utils::diffie_hellman::*;
use super::utils::*;
use super::messages::*;

use super::{P,G};

const I : &str = "email@email.com";

pub fn client(to_server: Sender<String>, from_server: Receiver<String>) {
    println!("\tClient: Generate keys");
    let (client_private, client_public) = generate_private_public(
        &get_nist_prime(),
        &G.to_biguint().unwrap());

    println!("\tClient: Sending ClientHello to Server");
    let hello = ClientHello::new(I, &client_public).serialize();
    to_server.send(hello).unwrap();

    println!("\tClient: Wait for ServerChallenge...");
    let server_challenge = from_server.recv().unwrap();
    println!("\tClient: ServerChallenge received. Calculating proof");

    let server_challenge = ServerChallenge::deserialize(&server_challenge);
    let server_public = biguint_from_string(&server_challenge.public_key);
    let salt = server_challenge.salt;
    let u = server_challenge.u.to_biguint().unwrap();

    let x = gen_sha256_int(vec![&salt.to_le_bytes(), P]);
    let s = server_public.modpow(&(client_private + u*x), &get_nist_prime());

    let hmac = hmac_s(&s, salt);

    let client_response = ClientResponse::new(hmac.result().code().to_vec());

    println!("\tClient: Sending proof to server...");
    to_server.send(client_response.serialize()).unwrap();

    println!("\tClient: Wait for ServerOk...");
    let server_ok = from_server.recv().unwrap();
    let server_ok = ServerOk::deserialize(&server_ok);

    println!("\tClient: Received ServerOk {:?}", server_ok);
    println!("\tClient: Done");
}
