* Remember the CBC bit-flipping attack?
* Using bitflipping for a byte, you can generate any of the 256 values a
  byte can represent... The question is, how do you know which value was
yielded
* Padding validation can be used to detect a specific value. If you were
  to go through all 256 values for the last byte, how many of them would
constitute valid padding?
  * Usually, one... but sometimes two. How can you discern which is
    which?
  * The second option depends on the preceding bytes... what if you
    changed one of them?
* Once you know which bits you flipped, and you know the resulting
  plaintext value, how can you get the original plaintext byte value?
* Can you use the same method for bytes before the last (assuming you
  cracked the succeeding bytes)?
