#[macro_use]
extern crate lazy_static;

use std::sync::mpsc;
use std::time::{Duration, SystemTime};
use std::thread;
use utils::*;
use utils::hmac::*;


const DATA : &[u8] = b"The quick brown fox jumped over the lazy dog";
const KEY_SIZE : usize = 20;

lazy_static! {
    pub static ref KEY: Vec<u8> = random_buffer(KEY_SIZE);
}

fn validate_mac(data: &[u8], hmac: &[u8]) -> bool {
    let expected = hmac_sha1(&KEY, data);

    let delay = Duration::from_millis(50);
    hmac.len() == expected.len() &&
        hmac.iter()
        .zip(expected.iter())
        .all(|(a,b)| {
            thread::sleep(delay);
            a == b
        })
}

fn find_hmac_length(data: &[u8]) -> usize {
    // For each length, get the duration for validating
    // a mac of that length, then sort by duration and pick
    // the longest duration
    //
    // In reality, we may have needed to run each length multiple
    // times and use some aggregation to account for external factors
    // (e.g. network)
    (0..100)
        .map(|i| {
            let time = SystemTime::now();
            validate_mac(data, &vec![0; i]);
            (i, time.elapsed().unwrap())})
        .max_by_key(|&(_, dur)| dur)
        .map(|(i, _)| i)
        .unwrap()
}

fn validate_last_byte(data: &[u8], prefix: &[u8]) -> std::time::Duration {
    let time = SystemTime::now();
    if validate_mac(&data, &prefix) {
        time.elapsed().unwrap()
    } else {
        std::time::Duration::from_millis(0)
    }
}

fn time_byte_validation(data: &[u8], prefix: &[u8]) -> std::time::Duration {
    let time = SystemTime::now();
    validate_mac(&data, &prefix);
    validate_mac(&data, &prefix);
    validate_mac(&data, &prefix);
    time.elapsed().unwrap()
}

fn crack_next_byte_concurrent(data: &[u8], prefix: &mut Vec<u8>, pos: usize) {
    let (tx, rx) = mpsc::channel();
    let threads = (0..std::u8::MAX)
        .map(|i| {
            let is_last_byte = pos == prefix.len() - 1;
            let mut prefix = prefix.clone();
            let data = data.to_vec();
            let tx = mpsc::Sender::clone(&tx);

            thread::spawn(move || {
                prefix[pos] = i;
                let time = if is_last_byte {
                    validate_last_byte(&data, &prefix)
                } else {
                    time_byte_validation(&data, &prefix)
                };
                let result = (i, time);
                tx.send(result).unwrap(); }) })
        .collect::<Vec<_>>();

    for thread in threads {
        thread.join().unwrap();
    }

    // Drop our tx handle, since while it's open the iteration below will never
    // finish.
    drop(tx);

    let results = rx.iter().collect::<Vec<_>>();

    prefix[pos] = results.iter()
        .max_by_key(|&(_, dur)| dur)
        .map(|&(b,_)| b)
        .unwrap();

}

fn find_hmac(data: &[u8]) -> Vec<u8> {
    let len = find_hmac_length(&data);
    println!("HMAC length is {}", len);

    let mut hmac = vec![0; len];
    for i in 0..len {
        let time = SystemTime::now();
        crack_next_byte_concurrent(data, &mut hmac, i);
        //crack_next_byte(data, &mut hmac, i);
        println!("{}, {:?}", hmac[i], time.elapsed());
    }
    println!("");

    return hmac
}


fn main() {
    println!("Real HMAC is {:?}", hmac_sha1(&KEY, &DATA));
    let hmac = find_hmac(&DATA);
    println!("Cracked HMAC is {:?}", hmac);
    println!("HMAC matches? {}", validate_mac(&DATA, &hmac));
}
