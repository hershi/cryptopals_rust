use openssl::symm::{Cipher, Crypter, Mode, encrypt, decrypt};
use super::xor;

pub fn ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    encrypt(
        cipher,
        key,
        None,
        input).unwrap()
}

pub fn ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    decrypt(
        cipher,
        key,
        None,
        input).unwrap()
}

pub fn cbc_encrypt(input: &[u8], key: &[u8], mut iv: Vec<u8>, pad: bool) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(
        cipher,
        Mode::Encrypt,
        key,
        None).unwrap();

    encrypter.pad(pad);

    let mut ciphertext = vec![0; input.len() + cipher.block_size()];
    let mut pos = 0;
    for chunk in input.chunks(cipher.block_size()) {
        let chunk = super::xor(chunk, &iv);
        let count = encrypter.update(&chunk, &mut ciphertext[pos..]).unwrap();
        iv = ciphertext[pos..pos+cipher.block_size()].to_vec();
        pos += count;
    }
    pos += encrypter.finalize(&mut ciphertext[pos..]).unwrap();
    ciphertext.truncate(pos);

    ciphertext.to_vec()
}

pub fn cbc_decrypt(input: &[u8], key: &[u8], iv: &Vec<u8>, pad: bool) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter = Crypter::new(
        cipher,
        Mode::Decrypt,
        key,
        None).unwrap();

    // ATTENTION: We are decrypting without padding! If the input is padded
    // then this will fail or give odd results because padding bytes would not
    // be stripped.
    decrypter.pad(pad);

    let mut raw_decrypted_bytes = vec![0; input.len() + cipher.block_size()];
    let count = decrypter.update(input, &mut raw_decrypted_bytes).unwrap();

    raw_decrypted_bytes.iter().take(count)
        .zip(iv.iter().chain(input.iter())) // iterator for IV bytes
        .map(|(b,i)| b^i)
        .collect::<Vec<u8>>()
}

pub fn ctr_encrypt(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    input.chunks(16)
        .zip(0u64..)
        .map(|(block, counter)| {
            let mut bytes = nonce.to_le_bytes().to_vec();
            bytes.extend_from_slice(&counter.to_le_bytes());
            println!("{:?}", bytes);
            let key_stream = cbc_encrypt(&bytes, key, vec![0;16], false);
            xor(block, &key_stream)})
        .fold(
            Vec::with_capacity(input.len()),
            |mut acc, mut block| { acc.append(&mut block); acc})
}

pub fn ctr_decrypt(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    ctr_encrypt(input, key, nonce)
}

