extern crate rand;
extern crate num_bigint as bigint;

mod messages;
mod utils;
mod client;
mod server;
mod mitm;

use std::sync::mpsc::{channel};
use std::thread;
use self::client::*;
use self::mitm::*;
use self::server::*;

const G : i32 = 2;
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

