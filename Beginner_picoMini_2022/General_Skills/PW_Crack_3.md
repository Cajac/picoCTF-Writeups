# PW Crack 3

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: Beginner picoMini 2022, General Skills, password_cracking, hashing
Author: LT 'SYREAL' JONES
  
Description:
Can you crack the password to get the flag?

Download the password checker here and you'll need the encrypted flag and the hash in the same directory too.

There are 7 potential passwords with 1 being correct. You can find these by examining the password checker script.

Hints:
1. To view the level3.hash.bin file in the webshell, do: $ bvi level3.hash.bin
2. The str_xor function does not need to be reverse engineered for this challenge.
```

## Solution

Lets start with analysing the Python script. The script looks like this (with some empty lines removed)
```python
import hashlib

### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level3.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level3.hash.bin', 'rb').read()

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

def level_3_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)
    
    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")

level_3_pw_check()

# The strings below are 7 possibilities for the correct password. 
#   (Only 1 is correct)
pos_pw_list = ["f09e", "4dcf", "87ab", "dba8", "752e", "3961", "f159"]
``` 

The description suggests that we should brute force the solution but lets check if there is an faster way.  
On many easier challenge you can sometimes just Google for the hash to find the corresponding plain text for it.  
So lets try that. Get the hash
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/PW_Crack_3]
└─$ xxd -p level3.hash.bin
65d9c68e03807969851a83b28bbebed1
```

But if you Google for it you are probably not going to find the answer.

So lets write a brute forcer by changing the `level_3_pw_check` function slightly 
```python
def level_3_pw_check(user_pw):
    user_pw_hash = hash_pw(user_pw)
    
    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")
```

We also need to add code to iterate through the array of possible passwords
```python
for pw in pos_pw_list:
    print("Testing password: %s" % pw)
    level_3_pw_check(pw)
```

Finally, we run the brute force script to get the flag
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/PW_Crack_3]
└─$ python pw_crack_3_get_flag.py  
Testing password: f09e
That password is incorrect
Testing password: 4dcf
That password is incorrect
Testing password: 87ab
That password is incorrect
Testing password: dba8
Welcome back... your flag, user:
picoCTF{<REDACTED>}
Testing password: 752e
That password is incorrect
Testing password: 3961
That password is incorrect
Testing password: f159
That password is incorrect
```

For additional information, please see the references below.

### References

- [Wikipedia - Exclusive or](https://en.wikipedia.org/wiki/Exclusive_or)
- [W3Schools - Python - List Comprehension](https://www.w3schools.com/python/python_lists_comprehension.asp)
- [GeeksforGeeks - zip() in Python](https://www.geeksforgeeks.org/zip-in-python/)
- [Wikipedia - MD5](https://en.wikipedia.org/wiki/MD5)
