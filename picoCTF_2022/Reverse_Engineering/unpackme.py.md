# unpackme.py

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2022, Reverse Engineering, packing
Author: LT 'SYREAL' JONES

Description:
Can you get the flag?

Reverse engineer this Python program.

Hints:
(None)
```

## Solution

Lets start by looking at the Python source code given (with some empty lines removed)
```python
import base64
from cryptography.fernet import Fernet

payload = b'gAAAAABiMD06eCisTWoohiYL5jHGdCte5LAviTFguZQSIyRLAWICJpmdrgxhdTB923h6eksddKpKH41I5-HGzI6xGF_7eb_1u0S2Phw2NvYGTF1KzE1-AU66FfIW6QXWnCpPHOS9CatNBuFXuyjEAx86Rld2E7GjvuKEOJJXx_GZE2JgAxnDmvcewoksfjVCCAwNqzixpUPKkIET2xmO4EsDqK4CUG8_JxP0HwSEzW4PH-hVpZrkyse4EodFPsjs7NVJF0hL1_8bP1TCiEEnFn7hCoTRRvlpYQ=='

key_str = 'correctstaplecorrectstaplecorrec'
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)
plain = f.decrypt(payload)
exec(plain.decode())
```

OK, so we have an encrypted payload that gets decrypted and then executed with the `exec` function.

Lets run the script and see what happens
```bash
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Reverse_Engineering/Unpackme.py]
└─$ python unpackme.flag.py 
What's the password? test
That password is incorrect.
```

Why not simply change the last `exec(plain.decode())` to `print(plain.decode())` and run the script again?  
Note, the flag is redacted below.
```bash
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Reverse_Engineering/Unpackme.py]
└─$ python unpackme.flag.py 

pw = input('What\'s the password? ')

if pw == 'batteryhorse':
  print('picoCTF{<REDACTED>}')
else:
  print('That password is incorrect.')

```

And there is the flag.

For additional information, please see the references below.

## References

- [programiz - Python exec()](https://www.programiz.com/python-programming/methods/built-in/exec)
