extern crate rand;
extern crate num_bigint as bigint;

mod messages;
mod utils;

use bigint::*;
use hmac::*;
use rand::prelude::*;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::thread;
use ::utils::diffie_hellman::*;
use self::utils::*;

pub use messages::*;

const G : i32 = 2;
const I : &str = "email@email.com";
const P : &[u8] = b"thisisdefinitelymyrealpassowrdforallmybankingaccounts";


fn main() {
    println!("Creating channels");
    let (client_send, mitm_recv_client) = channel();
    let (mitm_send_client, client_recv) = channel();

    let (mitm_send_server, server_recv) = channel();
    let (server_send, mitm_recv_server) = channel();

    println!("Spinning up server thread...");
    let server_thread = thread::spawn(move || {
        server(server_send, server_recv);
    });

    println!("Spinning up client thread...");
    let client_thread = thread::spawn(move || {
        client(client_send, client_recv);
    });

    println!("Spinning up MITM thread...");
    let mitm_thread = thread::spawn(move || {
        mitm(
            mitm_send_client, mitm_recv_client,
            mitm_send_server, mitm_recv_server);
    });


    server_thread.join().unwrap();
    client_thread.join().unwrap();
    mitm_thread.join().unwrap();
}

fn client(to_server: Sender<String>, from_server: Receiver<String>) {
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

fn server(to_client: Sender<String>, from_client: Receiver<String>) {
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

fn mitm(to_client: Sender<String>,
        from_client: Receiver<String>,
        to_server: Sender<String>,
        from_server: Receiver<String>) {
    let (mitm_private, mitm_public) = generate_private_public(
        &get_nist_prime(),
        &G.to_biguint().unwrap());

    let client_hello = &from_client.recv().unwrap();
    let client_hello = ClientHello::deserialize(&client_hello);
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

    let client_response = &from_client.recv().unwrap();
    let client_response = ClientResponse::deserialize(&client_response);
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

    println!("Trying to crack with {}. Result: {}", password, result);
    result
}


