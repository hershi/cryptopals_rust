* How is this different from challenge 12? Can you make it similar and
  reuse your solution?
* With the random length prefix, it's hard to know where *your* data
  starts. Can you craft your data to make it detectable?
* Can you use the code from challenges 8 or 11?
* Does your method mostly work, but has sporadic failures in decrypting
  bytes? Have you considered what happens when the last byte of the
random prefix matches the first byte of your input? Would this throw off
your detection logic?
* Like many things in programming, another layer may solve this issue
