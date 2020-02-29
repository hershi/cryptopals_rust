extern crate rand;
extern crate num_bigint as bigint;

use bigint::{BigInt, Sign, ToBigInt};
use hmac::*;
use rand::prelude::*;
use sha2::*;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;
use serde::{Serialize, Deserialize};
use utils::diffie_hellman::*;

const G : i32 = 2;
const K : i32 = 3;
const I : &str = "email@email.com";
const P : &[u8] = b"thisisdefinitelymyrealpassowrdforallmybankingaccounts";

fn main() {
    println!("Creating channels");
    let (server_send, client_recv) = channel();
    let (client_send, server_recv) = channel();

    println!("Spinning up server thread...");
    let server_thread = thread::spawn(move || {
        server(server_send, server_recv);
    });

    println!("Spinning up client thread...");
    let client_thread = thread::spawn(move || {
        client(client_send, client_recv);
    });

    server_thread.join().unwrap();
    client_thread.join().unwrap();
}

fn gen_h264_int(inputs: Vec<&[u8]>) -> BigInt {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.input(input);
    }

    let x_h = hasher.result();
    //println!("xH: {:?}", x_h);
    BigInt::from_bytes_le(Sign::Plus, x_h.as_slice())
}

#[derive(Serialize, Deserialize, Debug)]
struct ClientRegistration {
    email: String,
    salt: i32,
    verifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ClientHello {
    email: String,
    public_key: String,
}

struct UserRecord {
    salt: i32,
    verifier: BigInt,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerChallenge {
    salt: i32,
    public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ClientResponse {
    resp: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerOk {
    ok: bool,
}

fn client(to_server: Sender<String>, from_server: Receiver<String>) {
    let g = G.to_bigint().unwrap();
    let (private, public) = generate_private_public(&get_nist_prime(), &g);
    let hello = ClientHello{
        email: I.to_string(),
        public_key: public.to_str_radix(16),};

    println!("\tClient: public key: {:?}", public);
    let hello = serde_json::to_string(&hello).unwrap();
    to_server.send(hello).unwrap();

    let server_challenge = from_server.recv().unwrap();
    let server_challenge: ServerChallenge = serde_json::from_str(&server_challenge).unwrap();
    let server_public = BigInt::parse_bytes(server_challenge.public_key.as_bytes(), 16).unwrap();
    println!("\tClient: server public: {:?}", server_public);
}

fn server(to_client: Sender<String>, from_client: Receiver<String>) {
    println!("Server: Waiting for registration...");

    let user_recrod = gen_user_record();
    //println!("User record: {:?}", user_record);
    //
    println!("Server: Waiting for ClientHello...");
    let client_hello = &from_client.recv().unwrap();
    let client_hello: ClientHello = serde_json::from_str(&client_hello).unwrap();
    let client_public = BigInt::parse_bytes(client_hello.public_key.as_bytes(), 16).unwrap();
    println!("Server: Client public key: {:?}", client_public);

    let (private, public) = generate_private_public(
        &get_nist_prime(),
        &G.to_bigint().unwrap());

    let public = K.to_bigint().unwrap() * user_recrod.verifier + public;

    println!("Server: server public key: {:?}", public);
    let challenge = ServerChallenge{
        salt: user_recrod.salt,
        public_key: public.to_str_radix(16),
    };

    let challenge = serde_json::to_string(&challenge).unwrap();
    to_client.send(challenge);
}

fn gen_user_record() -> UserRecord {
    let mut rng = thread_rng();
    let salt = rng.gen::<i32>();
    //println!("Server Salt: {}", salt);

    let x = gen_h264_int(vec![&salt.to_le_bytes(), P]);
    //println!("Server x: {}", x);

    let n = get_nist_prime();
    let g = G.to_bigint().unwrap();
    let v = g.modpow(&x, &n);

    //println!("Server v: {}" , v);
    UserRecord{
        salt,
        verifier: v,
    }
}
