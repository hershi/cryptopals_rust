use bigint::*;
use hmac::*;
use rand::prelude::*;
use std::sync::mpsc::{Sender, Receiver};
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use ::utils::diffie_hellman::*;
use super::utils::*;
use super::messages::*;

use super::{G};

// So, how do we crack the password?
// The MITM can send their own ServerChallenge to the client. Specifically, they
// can use their own B, b, salt, and u - since the client has no way to authenticate
// that it is indeed the server that sent the message, they will respond with
// a valid response to the MITM challenge.
//
// The MITM can then try to "guess" the password and mimic what the server would
// have done to validate the client response against the known password. If the
// validation succeeds, then we found the password.
// Note that the only things the server needs to know to validate are:
// 1. The password - we have that - it's our guessed password
// 2. The server's (private:public) key-pair - we know it because we used the
//    MITM key-pair when talking to the client
// 3. The salt - we can just copy that from the original server challenge that
//    we intercepted
// 4. 'u' - we know that since we sent our own 'u' to the client (and we could
//    just copy it from the server's challenge anyway)
// 5. The client's public key - we know that one from intercepting the client
//    hello message.
//
// To crack the password, we just iterate over the list of candidate passwords
// and try to validate the client's response against them. Once we find one for
// which the validation succeeds, we found their password.
// We can then use that password to respond to the server as if we were the
// client, since the only thing we really need to know in order to authenticate
// is the password

pub fn mitm(to_client: Sender<String>,
        from_client: Receiver<String>,
        to_server: Sender<String>,
        from_server: Receiver<String>) {
    let (mitm_private, mitm_public) = generate_private_public(
        &get_nist_prime(),
        &G.to_biguint().unwrap());

    let client_hello = ClientHello::deserialize(&from_client.recv().unwrap());
    let client_public = biguint_from_string(&client_hello.public_key);
    println!("\t\t\tMITM: Received ClientHello from Client! Crafting MITM Hello...");

    let mitm_hello = ClientHello::new(&client_hello.email, &mitm_public);
    to_server.send(mitm_hello.serialize()).unwrap();

    let server_challenge = from_server.recv().unwrap();
    println!("\t\t\tMITM: Received ServerChallenge from Server! Crafting MITM Challenge...");

    let mitm_salt = thread_rng().gen::<i32>();
    let mitm_u = thread_rng().gen::<u128>();
    let mitm_challenge = ServerChallenge::new(
        mitm_salt,
        &mitm_public,
        mitm_u);
    to_client.send(mitm_challenge.serialize()).unwrap();
    println!("\t\t\tMITM: Sent crafted challenge to Client..");

    let client_response = ClientResponse::deserialize(&from_client.recv().unwrap());
    println!("\t\t\tMITM: Received ClientResponse from Client! Trying to guess password...");

    let password = crack_password(
        mitm_salt,
        &mitm_u.to_biguint().unwrap(),
        &client_public,
        &mitm_private,
        &client_response);

    if let Some(password) = password {
        let response = calculate_client_proof(
            &server_challenge,
            &password,
            &mitm_private);
        to_server.send(response.serialize()).unwrap();
    } else {
        // Couldn't crack the password, just forward to the server and hope for the
        // best :)
        to_server.send(client_response.serialize()).unwrap();
    }

    // Forward whatever the server response was
    to_client.send(from_server.recv().unwrap()).unwrap();
}

fn read_password_dict() -> Vec<String> {
    let input_file = File::open("src/passwords.txt").unwrap();
    let reader = BufReader::new(input_file);
    reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
}

fn crack_password(
    salt: i32,
    u: &BigUint,
    client_public: &BigUint,
    server_private: &BigUint,
    client_response: &ClientResponse) -> Option<String> {

    let candidates = read_password_dict();
    candidates.iter()
        .map(|p| (p, validate_guessed_password(
            &p, salt, u, client_public, server_private, client_response)))
        .filter(|&(_, correct)| correct)
        .map(|(p,_)| p.to_string())
        .nth(0)
}

fn validate_guessed_password(
    password: &str,
    salt: i32,
    u: &BigUint,
    client_public: &BigUint,
    server_private: &BigUint,
    client_response: &ClientResponse) -> bool {

    // Calculate `v` based on the guessed password, and from that
    let user_record = gen_user_record_with_salt(salt, password.as_bytes(), &G.to_biguint().unwrap());
    let v = user_record.verifier;
    let n = get_nist_prime();
    let s =
        (client_public * v.modpow(&u, &n))
        .modpow(&server_private, &n);

    let result = hmac_s(&s, user_record.salt)
        .verify(&client_response.resp).is_ok();

    println!("\t\t\tMITM: Trying to crack with {}. Result: {}", password, result);
    result
}
