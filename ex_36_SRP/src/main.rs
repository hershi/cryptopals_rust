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
struct ClientHello {
    email: String,
    public_key: String,
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
    let hello_msg = serde_json::to_string(&hello).unwrap();
    to_server.send(hello_msg).unwrap();
}

fn server(to_client: Sender<String>, from_client: Receiver<String>) {
    let state = server_init();
    //println!("Server init state: {:?}", state);
    println!("Server: Waiting for ClientHello...");
    let client_hello = &from_client.recv().unwrap();
    let client_hello: ClientHello = serde_json::from_str(&client_hello).unwrap();
    let client_public = BigInt::parse_bytes(client_hello.public_key.as_bytes(), 16).unwrap();

    println!("Server: Client public key: {:?}", client_public);
}

fn server_init() -> ServerChallenge {
    let mut rng = thread_rng();
    let salt = rng.gen::<i32>();
    //println!("Server Salt: {}", salt);

    let x = gen_h264_int(vec![&salt.to_le_bytes(), P]);
    //println!("Server x: {}", x);

    let n = get_nist_prime();
    let g = G.to_bigint().unwrap();
    let v = g.modpow(&x, &n);

    //println!("Server v: {}" , v);
    ServerChallenge{
        salt,
        public_key:  v.to_str_radix(16),
    }
}
