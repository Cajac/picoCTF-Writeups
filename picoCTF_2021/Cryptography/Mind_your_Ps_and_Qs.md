# Mind your Ps and Qs

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 20
Tags: picoCTF 2021, Cryptography
Author: SARA

Description:
In RSA, a small e value can be problematic, but what about N? 
Can you decrypt this? values

Hints:
1. Bits are expensive, I used only a little bit over 100 to save money
```

## Solution

Lets start by looking what we was given in the `values` file
```
Decrypt my super sick RSA:
c: 240986837130071017759137533082982207147971245672412893755780400885108149004760496
n: 831416828080417866340504968188990032810316193533653516022175784399720141076262857
e: 65537
```

We have a cipher text `c`, a modulus number `n` and the public key exponent `e`.

To solve this we need to factorize `n` into the primes `p` and `q`.

### Factorize n into p and q

Luckily smarter people than me have done that for us in [FactorDB](http://factordb.com/).  
And yes, the `n` value can be [found there](http://factordb.com/index.php?id=1100000002524292560).

If we want to script this we can use the [factordb-python CLI](https://pypi.org/project/factordb-pycli/)
```python
#!/usr/bin/python

from factordb.factordb import FactorDB

n = 831416828080417866340504968188990032810316193533653516022175784399720141076262857

f = FactorDB(n)
f.connect()
p, q = f.get_factor_list()

print(f"p = {p} and q = {q}")
```

Lets make sure its working before continuing
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Cryptography/Mind_your_Ps_and_Qs]
└─$ ~/python_venvs/gmpy2/bin/python factorize.py 
p = 1593021310640923782355996681284584012117 and q = 521911930824021492581321351826927897005221
```

We are good to go!

### Decrypt the flag

Next, we decrypt the message with some help of [gmpy2](https://pypi.org/project/gmpy2/)
```python
#!/usr/bin/python

from factordb.factordb import FactorDB
from gmpy2 import invert

# Given in the challenge
c = 240986837130071017759137533082982207147971245672412893755780400885108149004760496
n = 831416828080417866340504968188990032810316193533653516022175784399720141076262857
e = 65537

def decrypt(c, p, q, e):
     ph = (p-1) * (q-1)
     d = invert(e, ph)
     n = p * q
     return pow(c, d, n)

# Factorize n into p and q
f = FactorDB(n)
f.connect()
p, q = f.get_factor_list()

# Decrypt the flag
flag = decrypt(c, p, q, e)
print(bytes.fromhex(format(flag, 'x')).decode())
```

Finally, we run this script to get the flag
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Cryptography/Mind_your_Ps_and_Qs]
└─$ ~/python_venvs/gmpy2/bin/python decrypt.py  
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

### References

- [Wikipedia - RSA (cryptosystem)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [The RSA Cryptosystem - Concepts](https://cryptobook.nakov.com/asymmetric-key-ciphers/the-rsa-cryptosystem-concepts)
