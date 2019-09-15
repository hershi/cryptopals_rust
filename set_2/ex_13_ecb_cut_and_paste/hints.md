* Remember that ECB is stateless - each block is encrypted (and
  decrypted) independently
* The independence between blocks means that if you have two
  ciphertexts, you can cut and concatenate two ciphertexts as long as
you cut them at the block boundary
* Caveat - don't forget that the last block contains padding
* Can you control where the block boundary is? What would be a good
  place to cut it?
* Can you get a ciphertext prefix that ends with 'role='?
* What do you need to concatenate at the end of that prefix?
* Can you make a cypher text with the last block being a specific 5
  character string of your choice?
* Note that you need to be able to control the input as a byte-sequence (as opposed to a string, where some byte values may not be acceptable)
* Maybe you can reuse code from Challenge 11?
