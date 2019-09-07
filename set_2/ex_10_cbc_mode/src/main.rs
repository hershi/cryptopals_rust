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

fn cbc_encrypt(input: &[u8], key: &[u8], iv: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    let encrypted_chunks = input.chunks(cipher.block_size())
        .scan( iv, |iv, chunk| {
            let chunk = xor(chunk, iv);
            let encrypted_block = encrypt(cipher,
                                          key,
                                          None,
                                          &chunk).unwrap();
            *iv = encrypted_block.clone();
            println!("Encrypted_block size: {}", encrypted_block.len());
            Some(encrypted_block)
        }).collect::<Vec<_>>();

    encrypted_chunks.iter()
        .flat_map(|encrypted_chunk| encrypted_chunk.iter())
        .map(|x|*x)
        .collect()
}

fn cbc_encrypt2(input: &[u8], key: &[u8], mut iv: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(
        cipher,
        Mode::Encrypt,
        key,
        None).unwrap();

    let mut ciphertext = vec![0; input.len() + cipher.block_size()];
    let mut pos = 0;
    for chunk in input.chunks(cipher.block_size()) {
        let chunk = xor(chunk, &iv);
        let count = encrypter.update(&chunk, &mut ciphertext[pos..]).unwrap();
        println!("Encrypted chunk of size {}, wrote {} bytes",
                 chunk.len(),
                 count);
        iv = ciphertext[pos..pos+cipher.block_size()].to_vec();
        pos += count;
    }
    pos += encrypter.finalize(&mut ciphertext[pos..]).unwrap();
    println!("After finalization {} bytes", pos);
    ciphertext.truncate(pos);

    ciphertext.to_vec()
}

fn cbc_decrypt2(input: &[u8], key: &[u8], mut iv: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter = Crypter::new(
        cipher,
        Mode::Decrypt,
        key,
        None).unwrap();

    let mut plaintext = vec![0; input.len()];
    let mut pos = 0;
    for chunk in input.chunks(cipher.block_size()) {
        let mut decrypted_chunk = vec![0; cipher.block_size() * 2];
        let count = decrypter.update(&chunk, &mut decrypted_chunk).unwrap();
        println!("Decrypted chunk of size {}, wrote {} bytes",
                 chunk.len(),
                 count);
        decrypted_chunk = xor(&decrypted_chunk, &iv);
        plaintext[pos..].clone_from_slice(&decrypted_chunk);
        pos += count;

        iv = chunk.to_vec();
    }
    let count = decrypter.finalize(&mut plaintext[pos..]).unwrap();
    println!("After finalization {} bytes {}", count, pos+count);
    pos += count;
    plaintext.truncate(pos);

    plaintext.to_vec()
}

fn cbc_decrypt(input: &[u8], key: &[u8], iv: Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();

    let decrypted_chunks = input.chunks(cipher.block_size() * 2)
        .scan( iv, |iv, chunk| {
            let plaintext_bytes = decrypt(
                cipher,
                key,
                None,
                chunk).unwrap();
            let plaintext_bytes = xor(&plaintext_bytes, iv);
            *iv = chunk.to_vec();
            Some(plaintext_bytes)})
        .collect::<Vec<_>>();

    decrypted_chunks.iter()
        .flat_map(|decrypted_chunk| decrypted_chunk.iter())
        .map(|x|*x)
        .collect()
}

fn main() {
    let block_size = Cipher::aes_128_ecb().block_size();
    let iv = vec![0u8; block_size];
    let key = KEY.as_bytes();
    let input = "0123456789ABCDEF".as_bytes();
    //let input = read_input().iter().cloned().take(32).collect::<Vec<u8>>();;
    let encrypted = cbc_encrypt2(&input, &key, iv.clone());
    let decrypted = cbc_decrypt2(&encrypted, &key, iv.clone());
    //let decrypted = cbc_decrypt(&encrypted, &key, iv.clone());

    println!("Block size: {}", block_size);
    println!("Input message: {}", input.len());
    println!("Encrypted message: {}\nMessage{:?}", encrypted.len(), encrypted);
    println!("Decrypted message: {}\nMessage{:?}", decrypted.len(), decrypted);
    println!("Decrypted string: {}", to_string(&decrypted));
    //println!("Decrypted message: {}", decrypted.len());

    //println!("message: {}", to_string(&decrypted));
}

