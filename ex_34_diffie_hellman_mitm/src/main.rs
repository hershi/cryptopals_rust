extern crate num_bigint as bigint;

use utils::diffie_hellman::*;
use utils::*;
use utils::encoding::*;
use utils::encryption::*;
use utils::sha1::*;
use std::thread;
use std::sync::mpsc::{Sender, Receiver, channel};
use bigint::*;

const MESSAGE_A : &[u8] = b"Message from A to B";
const MESSAGE_B : &[u8] = b"Message from B to A";

const KEY_SIZE :usize = 16;
const IV_SIZE :usize = 16;

fn encrypt_message_with_iv(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let iv = random_buffer(IV_SIZE);
    let encrypted_message = cbc_encrypt(
        plaintext,
        &key,
        iv.clone(),
        true);

    iv.iter()
        .chain(encrypted_message.iter())
        .cloned()
        .collect::<Vec<u8>>()
}

fn decrypt_message(key: &[u8], message: &[u8]) -> Vec<u8> {
    let (iv, message)  = message.split_at(IV_SIZE);
    cbc_decrypt(message, key, iv, true)
}

fn alice(to_bob: Sender<Vec<u8>>, from_bob: Receiver<Vec<u8>>) {
    let (p,g) = generate_pg();
    let (private, public) = generate_private_public(&p, &g);

    println!("Sending `p` to Bob");
    to_bob.send(p.to_bytes_le()).unwrap();
    println!("Sending `g` to Bob");
    to_bob.send(g.to_bytes_le()).unwrap();
    println!("Sending `A` to Bob");
    to_bob.send(public.to_bytes_le()).unwrap();
    println!("Sent to Bob");

    let public_other = BigUint::from_bytes_le(&from_bob.recv().unwrap());
    println!("Received `B` from Bob");

    let session_key = derive_session_key(&p, &private, &public_other);
    println!("Session Key for Alice:");

    let encryption_key = sha1(&session_key.to_bytes_le())
        .iter()
        .take(KEY_SIZE)
        .cloned()
        .collect::<Vec<u8>>();


    assert!(encryption_key.len() == KEY_SIZE);

    println!("Sending message to Bob");
    let message = encrypt_message_with_iv(&encryption_key, MESSAGE_A);
    to_bob.send(message).unwrap();

    println!("Waiting for message from Bob");
    let message = from_bob.recv().unwrap();
    println!("Received message from Alice with len {}", message.len());

    let decrypted = decrypt_message(&encryption_key, &message);
    println!("Decrypted message from Bob `{}`", to_string(&decrypted));
}

fn bob(to_alice: Sender<Vec<u8>>, from_alice: Receiver<Vec<u8>>) {
    println!("\t\tWaiting for Alice...");
    let p = BigUint::from_bytes_le(&from_alice.recv().unwrap());
    println!("\t\tReceived `p` from Alice");
    let g = BigUint::from_bytes_le(&from_alice.recv().unwrap());
    println!("\t\tReceived `g` from Alice");
    let public_other = BigUint::from_bytes_le(&from_alice.recv().unwrap());
    println!("\t\tReceived `A` from Alice");

    let (private, public) = generate_private_public(&p, &g);

    println!("\t\tSending `B` to Alice");
    to_alice.send(public.to_bytes_le()).unwrap();

    let session_key = derive_session_key(&p, &private, &public_other);
    println!("\t\tSession Key for Bob");

    let encryption_key = sha1(&session_key.to_bytes_le())
        .iter()
        .take(KEY_SIZE)
        .cloned()
        .collect::<Vec<u8>>();

    assert!(encryption_key.len() == KEY_SIZE);

    println!("\t\tSending message to Alice");
    let message = encrypt_message_with_iv(&encryption_key, MESSAGE_B);
    to_alice.send(message).unwrap();

    println!("\t\tWaiting for message from Alice");
    let message = from_alice.recv().unwrap();
    println!("\t\tReceived message from Alice with len {}", message.len());

    let decrypted = decrypt_message(&encryption_key, &message);
    println!("\t\tDecrypted message from Alice `{}`", to_string(&decrypted));
}

fn mitm(
        to_alice: Sender<Vec<u8>>,
        to_bob: Sender<Vec<u8>>,
        from_alice: Receiver<Vec<u8>>,
        from_bob: Receiver<Vec<u8>>) {
    println!("\t\t\t\tWaiting to receive from Alice...");
    let p = BigUint::from_bytes_le(&from_alice.recv().unwrap());
    println!("\t\t\t\tReceived `p` from Alice");
    let g = BigUint::from_bytes_le(&from_alice.recv().unwrap());
    println!("\t\t\t\tReceived `g` from Alice");
    let public_other = BigUint::from_bytes_le(&from_alice.recv().unwrap());
    println!("\t\t\t\tReceived `A` from Alice");

    to_bob.send(p.to_bytes_le()).unwrap();
    println!("\t\t\t\tSent `p` to Bob");
    to_bob.send(g.to_bytes_le()).unwrap();
    println!("\t\t\t\tSent `g` to Bob");
    to_bob.send(p.to_bytes_le()).unwrap();
    println!("\t\t\t\tSent `p` to Bob");

    let public_bob = BigUint::from_bytes_le(&from_bob.recv().unwrap());
    println!("\t\t\t\tReceived `B` from Bob");
    to_alice.send(p.to_bytes_le()).unwrap();
    println!("\t\t\t\tSent `p` to Alice");

    let encryption_key = sha1(&0.to_biguint().unwrap().to_bytes_le())
        .iter()
        .take(KEY_SIZE)
        .cloned()
        .collect::<Vec<u8>>();

    let message = from_alice.recv().unwrap();
    let decrypted = decrypt_message(&encryption_key, &message);
    println!("\t\t\t\tMITM broken message from Alice to Bob `{}`", to_string(&decrypted));
    to_bob.send(message).unwrap();

    let message = from_bob.recv().unwrap();
    let decrypted = decrypt_message(&encryption_key, &message);
    println!("\t\t\t\tMITM broken message from Bob to Alice `{}`", to_string(&decrypted));
    to_alice.send(message).unwrap();
}

fn main() {
    let (alice_send, mitm_recv_alice) = channel();
    let (bob_send, mitm_recv_bob) = channel();
    let (mitm_send_alice, alice_recv) = channel();
    let (mitm_send_bob, bob_recv) = channel();

    let thread_alice = thread::spawn(move || {
        alice(alice_send, alice_recv);
    });

    let thread_bob = thread::spawn(move || {
        bob(bob_send, bob_recv);
    });

    let thread_mitm = thread::spawn(move || {
        mitm(
            mitm_send_alice,
            mitm_send_bob,
            mitm_recv_alice,
            mitm_recv_bob);
    });

    thread_alice.join().unwrap();
    thread_bob.join().unwrap();
    thread_mitm.join().unwrap();
}
