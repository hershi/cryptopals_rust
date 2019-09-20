* The phrasing of the question is a bit confusing - what does `The function should quote out the ";" and "=" characters` really mean? Just replace `=` with `"="` and `;` with `";"`
* As it turns out, this doesn't really matter - the soultion to this
  question doesn't requrie you to have any `=` or `;` in the user input
* The hints at the end of the challenge text tell you most of the
  story...
* Can you XOR the problematic bits in the user input to make CBC
  bitflipping easy to determine
* Note that you need the parts you want to flip to all be in the same
  block... Which is quite easy, given that the user data is already
block aligned
