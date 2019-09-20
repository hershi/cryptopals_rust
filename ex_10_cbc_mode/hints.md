# The instructions are a bit confusing - it asks you to create an
encryption function, but then talks about decrypting the input file.
What you actually need to complete this challenge  is a cbc *decryption*
function, that does the reverse of what a CBC encryption function does.
Ideally, though, you should implement both CBC encrypt and CBC decrypt
# Note that the input file is encrypted with no padding. The default for
OpenSSL (at least when used via the [Rust openssl
crate](https://docs.rs/openssl/0.10.24/openssl/symm/struct.Cipher.html)
is to use padding - and that would result in an error during `finalize`
# Helpful visualization of CBC encrypt/decrypt can be found on the
[wikipedia page for Block Cipher Operation
Mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC))
