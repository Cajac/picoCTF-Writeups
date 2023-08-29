# New Caesar

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 60
Tags: picoCTF 2021, Cryptography
Author: MADSTACKS

Description:
We found a brand new type of encryption, can you break the secret code? 
(Wrap with picoCTF{}) 

kjlijdliljhdjdhfkfkhhjkkhhkihlhnhghekfhmhjhkhfhekfkkkjkghghjhlhghmhhhfkikfkfhm 
new_caesar.py

Hints:
1. How does the cipher work if the alphabet isn't 26 letters?
2. Even though the letters are split up, the same paradigms still apply
```

## Solution

### Analyze the cipher

Lets start by looking at the python source
```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c))
		enc += ALPHABET[int(binary[:4], 2)]
		enc += ALPHABET[int(binary[4:], 2)]
	return enc

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]

flag = "redacted"
key = "redacted"
assert all([k in ALPHABET for k in key])
assert len(key) == 1

b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):
	enc += shift(c, key[i % len(key)])
print(enc)
```

We have two functions:
 * `b16_encode` which encodes the text as base16, that is encodes each nibble as a character
 * `shift` which applies a caesar variant shift on each character

We also see that the length of the key is only one byte, so we can brute force it for all possible keys.

### Write a brute force decoder

We need a `b16_decode` function but we really don't need to reverse the shift function since we will try all possible keys.

The total script looks like this
```python
#!/usr/bin/python

import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]
    
def b16_decode(enc):
    plain = ""
    for i in range(0, len(enc), 2):
        v1 = ord(enc[i]) - LOWERCASE_OFFSET
        v2 = ord(enc[i+1]) - LOWERCASE_OFFSET
        plain += chr(v1*16 + v2)
    return plain

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]

enc_flag = "kjlijdliljhdjdhfkfkhhjkkhhkihlhnhghekfhmhjhkhfhekfkkkjkghghjhlhghmhhhfkikfkfhm"

for key in ALPHABET:
    print(f"Trying key: {key}")
    dec = ""
    for c in enc_flag:
        dec += shift(c, key)
    flag_cand = b16_decode(dec)
    if flag_cand.isprintable():
        print(f"Flag: picoCTF{{{flag_cand}}}")
```

### Get the flag

Then we make sure the script is executable and run it
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Cryptography/New_Caesar]
└─$ chmod +x bf_cipher.py     

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Cryptography/New_Caesar]
└─$ ./bf_cipher.py       
Trying key: a
Trying key: b
Trying key: c
Trying key: d
Trying key: e
Flag: picoCTF{íü×üý·×¹éë½î»ì¿±º¸é°½¾¹¸éîíêº½¿º°»¹ìéé°}
Trying key: f
Trying key: g
Trying key: h
Trying key: i
Trying key: j
Trying key: k
Trying key: l
Flag: picoCTF{TcNcd.N PR$U"S&(!/P'$% /PUTQ!$&!'" SPP'}
Trying key: m
Flag: picoCTF{et_tu?_<REDACTED>}
Trying key: n
Trying key: o
Trying key: p
```

We get three possible keys but only one makes sense.

For additional information, please see the references below.

## References

- [Wikipedia - Modulo](https://en.wikipedia.org/wiki/Modulo)
- [Wikipedia - Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher)
