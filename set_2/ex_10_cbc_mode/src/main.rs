use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use data_encoding::BASE64;
use openssl::symm::{encrypt, decrypt, Cipher, Crypter, Mode};
use utils::*;
use utils::encoding::*;

const KEY : &str = "YELLOW SUBMARINE";

fn read_input() -> Vec<u8> {
    let input_file = File::open("src/input.txt").unwrap();
    let reader = BufReader::new(input_file);
    let input_string = reader.lines()
        .map(|x|x.unwrap())
        .collect::<Vec<String>>()
        .join("");

    BASE64.decode(input_string.as_bytes()).unwrap()
}

fn cbc_encrypt(input: &[u8], key: &[u8], mut iv: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(
        cipher,
        Mode::Encrypt,
        key,
        None).unwrap();

    encrypter.pad(false);

    let mut ciphertext = vec![0; input.len() + cipher.block_size()];
    let mut pos = 0;
    for chunk in input.chunks(cipher.block_size()) {
        let chunk = xor(chunk, &iv);
        let count = encrypter.update(&chunk, &mut ciphertext[pos..]).unwrap();
        println!("Encrypted chunk size {}, count {}", chunk.len(), count);
        iv = ciphertext[pos..pos+cipher.block_size()].to_vec();
        pos += count;
    }
    pos += encrypter.finalize(&mut ciphertext[pos..]).unwrap();
    ciphertext.truncate(pos);

    ciphertext.to_vec()
}

fn cbc_decrypt(input: &[u8], key: &[u8], mut iv: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter = Crypter::new(
        cipher,
        Mode::Decrypt,
        key,
        None).unwrap();
    decrypter.pad(false);

    let mut plaintext = vec![0; input.len()];
    let mut pos = 0;
    for chunk in input.chunks(cipher.block_size()) {
        let mut decrypted_chunk = vec![0; cipher.block_size() * 2];
        let count = decrypter.update(&chunk, &mut decrypted_chunk).unwrap();
        decrypted_chunk.truncate(count);
        decrypted_chunk = xor(&decrypted_chunk, &iv);
        iv = chunk.to_vec();
        plaintext[pos..pos + decrypted_chunk.len()].clone_from_slice(&decrypted_chunk);
        pos += count;
    }

    // We don't use padding, so expecting finalize to always result in 0
    let mut decrypted_chunk = vec![0; cipher.block_size() * 2];
    let count = decrypter.finalize(&mut decrypted_chunk).unwrap();
    assert_eq!(count, 0);

    plaintext.truncate(pos);
    plaintext.to_vec()
}

fn main() {
    let block_size = Cipher::aes_128_ecb().block_size();
    let iv = vec![0u8; block_size];
    let key = KEY.as_bytes();

    let mut encrypted = read_input();
    //let mut encrypted = cbc_encrypt(&"0123456789ABCDEF".as_bytes(), &key, iv.clone());
    let decrypted = cbc_decrypt(&encrypted, &key, iv.clone());
    println!("{}", to_string(&decrypted));
}

