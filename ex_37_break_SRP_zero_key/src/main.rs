extern crate rand;
extern crate num_bigint as bigint;
extern crate hmac;

use bigint::*;
use hmac::*;
use rand::prelude::*;
use sha2::*;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;
use serde::{Serialize, Deserialize};
use utils::diffie_hellman::*;

type HmacSha256 = Hmac<Sha256>;

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
        client_no_password(client_send, client_recv);
    });

    server_thread.join().unwrap();
    client_thread.join().unwrap();
}

fn gen_sha256_int(inputs: Vec<&[u8]>) -> BigUint {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.input(input);
    }

    let x_h = hasher.result();
    BigUint::from_bytes_le(x_h.as_slice())
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

impl ClientHello {
    fn new(email: &str, public_key: &BigUint) -> ClientHello {
        ClientHello{
            email: email.to_string(),
            public_key: biguint_to_string(&public_key),}
    }

    fn new_msg(email: &str, public_key: &BigUint) -> String {
        let hello = ClientHello::new(email, public_key);
        serde_json::to_string(&hello).unwrap()
    }
}

struct UserRecord {
    salt: i32,
    verifier: BigUint,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerChallenge {
    salt: i32,
    public_key: String,
}

impl ServerChallenge {
    fn new(salt: i32, public_key: &BigUint) -> ServerChallenge {
        ServerChallenge{
            salt,
            public_key: biguint_to_string(&public_key),}
    }

    fn new_msg(salt: i32, public_key: &BigUint) -> String {
        let challenge = ServerChallenge::new(salt, public_key);
        serde_json::to_string(&challenge).unwrap()
    }
}


#[derive(Serialize, Deserialize, Debug)]
struct ClientResponse {
    resp: Vec<u8>,
}

impl ClientResponse {
    fn new(resp: Vec<u8>) -> ClientResponse {
        ClientResponse{resp}
    }

    fn new_msg(resp: Vec<u8>) -> String {
        serde_json::to_string(&ClientResponse::new(resp)).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerOk {
    ok: bool,
}

impl ServerOk {
    fn new(ok: bool) -> ServerOk {
        ServerOk{ok}
    }

    fn new_msg(ok:bool) -> String {
        serde_json::to_string(&ServerOk::new(ok)).unwrap()
    }
}

fn biguint_to_string(x: &BigUint) -> String {
    x.to_str_radix(16)
}

fn biguint_from_string(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).unwrap()
}

fn client_no_password(to_server: Sender<String>, from_server: Receiver<String>) {
    println!("\tClient: Generate keys");
    let n = get_nist_prime() * 5u32;
    let zero = 0.to_biguint().unwrap();

    let client_public = n.clone();

    println!("\tClient: Sending ClientHello to Server");
    let hello = ClientHello::new_msg(I, &client_public);
    to_server.send(hello).unwrap();

    println!("\tClient: Wait for ServerChallenge...");
    let server_challenge = from_server.recv().unwrap();
    let server_challenge: ServerChallenge = serde_json::from_str(&server_challenge).unwrap();
    let salt = server_challenge.salt;

    println!("\tClient: ServerChallenge received. Calculating proof");

    let s = zero.clone();

    let mut hasher = Sha256::new();
    hasher.input(s.to_bytes_le());
    let mut hmac = HmacSha256::new_varkey(&salt.to_le_bytes()).unwrap();
    hmac.input(&hasher.result());

    println!("\tClient: Sending proof to server...");
    let client_response = ClientResponse::new_msg(hmac.result().code().to_vec());
    to_server.send(client_response).unwrap();

    println!("\tClient: Wait for ServerOk...");
    let server_ok = from_server.recv().unwrap();
    let server_ok: ServerOk = serde_json::from_str(&server_ok).unwrap();

    println!("\tClient: Received ServerOk {:?}", server_ok);
    println!("\tClient: Done");
}

fn server(to_client: Sender<String>, from_client: Receiver<String>) {
    println!("Server:Rregistering user");

    let user_record = gen_user_record();

    println!("Server: Waiting for ClientHello...");
    let client_hello = &from_client.recv().unwrap();
    let client_hello: ClientHello = serde_json::from_str(&client_hello).unwrap();
    let client_public = biguint_from_string(&client_hello.public_key);

    let (server_private, server_public) = generate_private_public(
        &get_nist_prime(),
        &G.to_biguint().unwrap());

    // In theory, we should have used the email from client_hello to retrieve
    // the user record, but in the context of this exerices we skip over the
    // registration path and already know the user record
    let server_public = K.to_biguint().unwrap() * user_record.verifier.clone() + server_public;

    let challenge = ServerChallenge::new_msg(user_record.salt.clone(), &server_public);
    to_client.send(challenge).unwrap();

    let u = gen_sha256_int(vec![
                            &client_public.to_bytes_le(),
                            &server_public.to_bytes_le()]);

    let n = get_nist_prime();
    let s = (client_public * user_record.verifier.modpow(&u, &n))
        .modpow(&server_private, &n);

    let mut hasher = Sha256::new();
    hasher.input(s.to_bytes_le());
    let mut hmac = HmacSha256::new_varkey(&user_record.salt.to_le_bytes()).unwrap();
    hmac.input(&hasher.result());

    println!("Server: Waiting for ClientResponse...");
    let client_response = &from_client.recv().unwrap();
    let client_response: ClientResponse = serde_json::from_str(&client_response).unwrap();

    let ok = hmac.verify(&client_response.resp).is_ok();

    println!("Server: Validation succeeded? {}; sending response", ok);
    let server_ok = ServerOk::new_msg(ok);
    to_client.send(server_ok).unwrap();
    println!("Server: Done");
}

fn gen_user_record() -> UserRecord {
    let mut rng = thread_rng();
    let salt = rng.gen::<i32>();
    //println!("Server Salt: {}", salt);

    let x = gen_sha256_int(vec![&salt.to_le_bytes(), P]);
    //println!("Server x: {}", x);

    let g = G.to_biguint().unwrap();
    let v = g.modpow(&x, &get_nist_prime());

    UserRecord{
        salt,
        verifier: v,
    }
}
