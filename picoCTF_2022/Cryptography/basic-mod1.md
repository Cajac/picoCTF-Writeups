# basic-mod1

- [Challenge information](#challenge-information)
- [Solution](#solution)

## Challenge information
```
Points: 100
Tags: picoCTF 2022, Cryptography
Author: WILL HONG

Description:
We found this weird message being passed around on the servers, we think we have a working decryption scheme.
Download the message here.
 
Take each number mod 37 and map it to the following character set: 0-25 is the alphabet (uppercase), 
26-35 are the decimal digits, and 36 is an underscore.
 
Wrap your decrypted message in the picoCTF flag format (i.e. picoCTF{decrypted_message})

Hints:
1. Do you know what mod 37 means?
2. mod 37 means modulo 37. It gives the remainder of a number after being divided by 37.
```

## Solution

Lets use the instructions above to create a small Python script called `get_flag.py` to solve this challenge

```python
#!/usr/bin/python

# Read the encoded flag as string
with open("message.txt", 'r') as fh:
    enc_string = fh.read().strip()

# Convert to array of numbers
enc_numbers = map(int, enc_string.split())

# Create decode array
base_37 = []
for i in range(26):
    base_37 += chr(ord('A') + i)
for i in range(10):
    base_37 += chr(ord('0') + i)
base_37 += '_'

# Decode flag and print it
flag = []
for x in enc_numbers:
    flag += base_37[x % 37]
print('picoCTF{%s}' % "".join(flag))
```

Then make the script executable and run it
```
┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Cryptography/Basic_Mod1]
└─$ chmod +x get_flag.py  

┌──(kali㉿kali)-[/picoCTF/picoCTF_2022/Cryptography/Basic_Mod1]
└─$ ./get_flag.py
picoCTF{<REDACTED>}
```
