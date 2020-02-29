extern crate rand;
extern crate num_bigint as bigint;

use bigint::{BigInt, Sign, ToBigInt};
use rand::prelude::*;
use sha2::*;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;
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
    BigInt::from_signed_bytes_le(x_h.as_slice())
}

fn client(to_server: Sender<Vec<u8>>, from_server: Receiver<Vec<u8>>) {
}

fn server(to_client: Sender<Vec<u8>>, from_client: Receiver<Vec<u8>>) {
    let state = server_init();
    println!("Server init state: {:?}", state);
}

fn server_init() -> (i32, BigInt) {
    let mut rng = thread_rng();
    let salt = rng.gen::<i32>();
    //println!("Server Salt: {}", salt);

    let x = gen_h264_int(vec![&salt.to_le_bytes(), P]);
    //println!("Server x: {}", x);

    let n = get_nist_prime();
    let g = G.to_bigint().unwrap();
    let v = g.modpow(&x, &n);

    //println!("Server v: {}" , v);
    (salt, v)
}
