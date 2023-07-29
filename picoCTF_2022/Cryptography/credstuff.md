# credstuff

- [Challenge information](credstuff.md#challenge-information)
- [Solution](credstuff.md#solution)

## Challenge information
```
Points: 100
Tags: picoCTF 2022, Cryptography
Author: WILL HONG / LT 'SYREAL' JONES

Description:
We found a leak of a blackmarket website's login credentials. 

Can you find the password of the user cultiris and successfully decrypt it?
Download the leak here.

The first user in usernames.txt corresponds to the first password in passwords.txt. 
The second user corresponds to the second password, and so on.

Hints:
1. Maybe other passwords will have hints about the leak?
```

## Solution

Lets start by unpacking the tar-file and looking at the containing files
```
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Cryptography/Credstuff]
└─$ tar xvf leak.tar 
leak/
leak/passwords.txt
leak/usernames.txt
  
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Cryptography/Credstuff]
└─$ cd leak                  
                                                                                                                                
┌──(kali㉿kali)-[/picoCTF_2022/Cryptography/Credstuff/leak]
└─$ head passwords.txt 
CMPTmLrgfYCexGzJu6TbdGwZa
GK73YKE2XD2TEnvJeHRBdfpt2
UukmEk5NCPGUSfs5tGWPK26gG
kaL36YJtvZMdbTdLuQRx84t85
K9gzHFpwF2azPayAUSrcL8fJ9
rYrtRbkHvJzPmDwzD6gSDbAE3
kfcVXjcFkvNQQPpATErx6eVDd
kDrPVvMakUsNd7BvmJtK3ACY4
dvDvWjzXNk8WwqEzJ5P2FP5YH
86L5w4sH9ZXTCPAa5ExMSPFNh
                                                                                                  
┌──(kali㉿kali)-[/picoCTF_2022/Cryptography/Credstuff/leak]
└─$ head usernames.txt 
engineerrissoles
icebunt
fruitfultry
celebritypentathlon
galoshesopinion
favorboeing
bindingcouch
entersalad
ruthlessconfidence
coupleelevator
```

Lets check what line number the user is located at with `grep -n`
```
┌──(kali㉿kali)-[/picoCTF_2022/Cryptography/Credstuff/leak]
└─$ grep -n cultiris usernames.txt 
378:cultiris
```

Lets use `cat -n` in a similar fashion the get the corresponding password
```
┌──(kali㉿kali)-[/picoCTF_2022/Cryptography/Credstuff/leak]
└─$ cat -n passwords.txt| grep 378
   378  cvpbPGS{P7e1S_54I35_71Z3}
```

Hhm, the password looks like it's [ROT-13](https://en.wikipedia.org/wiki/ROT13) encoded (or any other number of rotations).

Lets not bother about the exact number of rotations and brute force it in Python which a script called `bf.py`
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

enc_flag = "cvpbPGS{P7e1S_54I35_71Z3}"

for i in range(1, alpha_len+1):
    plain = shift(enc_flag, i)
    if ('picoCTF' in plain):
        print("ROT-%02d: %s" % (i, plain))

```

Now run the script to get the flag
```
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Cryptography/Credstuff]
└─$ ./bf.py 
ROT-13: picoCTF{<REDACTED>}

```

This time it was standard ROT-13.
