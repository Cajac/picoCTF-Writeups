# rotation

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2023, Cryptography
Author: LOIC SHEMA

Description:
You will find the flag after decrypting this file

Download the encrypted flag here.

Hints:
1. Sometimes rotation is right
```

## Solution

### CyberChef solution

Open the file in [CyberChef](https://gchq.github.io/CyberChef/) and use the 'ROT13' recipe.  
The default rotation is 13 steps. Change the amount until you find the flag. The correct amount is 18.

### Python solution

Even though it takes a bit longer time it's more fun to write a small python script called `solve.py` to bruteforce the challenge.

```python
#!/usr/bin/python

import string

alphabet = string.ascii_lowercase
alpha_len = len(alphabet)

def shift(cipher_text, key):
    result = ''
    for c in cipher_text:
        if c.islower():
            result += alphabet[(alphabet.index(c) + key) % alpha_len]
        elif c.isupper():
            result += alphabet[(alphabet.index(c.lower()) + key) % alpha_len].upper()
        else:
            result += c
    return result

# Read the encoded flag
with open("encrypted.txt", 'r') as fh:
    enc_flag = fh.read().strip()

for i in range(1, alpha_len+1):
    plain = shift(enc_flag, i)
    if ('picoCTF' in plain):
        print("ROT-%02d: %s" % (i, plain))
```

Then make the script executable and run it
```
┌──(kali㉿kali)-[/picoCTF/picoCTF_2023/Cryptography/rotation]
└─$ chmod +x solve.py

┌──(kali㉿kali)-[/picoCTF/picoCTF_2023/Cryptography/rotation]
└─$ ./solve.py
ROT-18: picoCTF{<REDACTED>}
```

For additional information, please see the references below.

### References

- [Wikipedia - ROT13](https://en.wikipedia.org/wiki/ROT13)
