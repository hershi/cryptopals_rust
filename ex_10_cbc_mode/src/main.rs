use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use data_encoding::BASE64;
use openssl::symm::{Cipher, Crypter, Mode};
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
        iv = ciphertext[pos..pos+cipher.block_size()].to_vec();
        pos += count;
    }
    pos += encrypter.finalize(&mut ciphertext[pos..]).unwrap();
    ciphertext.truncate(pos);

    ciphertext.to_vec()
}

fn cbc_decrypt(input: &[u8], key: &[u8], iv: &Vec<u8>) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter = Crypter::new(
        cipher,
        Mode::Decrypt,
        key,
        None).unwrap();
    decrypter.pad(false);

    let mut raw_decrypted_bytes = vec![0; input.len() + cipher.block_size()];
    let mut count = decrypter.update(input, &mut raw_decrypted_bytes).unwrap();
    count += decrypter.finalize(&mut raw_decrypted_bytes[count..]).unwrap();

    raw_decrypted_bytes.iter().take(count)
        .zip(iv.iter().chain(input.iter())) // iterator for IV bytes
        .map(|(b,i)| b^i)
        .collect::<Vec<u8>>()
}

fn main() {
    let block_size = Cipher::aes_128_ecb().block_size();
    let iv = vec![0u8; block_size];
    let key = KEY.as_bytes();

    let input = read_input();
    let decrypted = cbc_decrypt(&input, &key, &iv);
    println!("{}", to_string(&decrypted));

    let encrypted = cbc_encrypt(&decrypted, &key, iv.clone());
    assert_eq!(encrypted, input);
}

