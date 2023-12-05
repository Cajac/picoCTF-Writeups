# repetitions

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: picoCTF 2023, General Skills, base64
Author: THEONESTE BYAGUTANGAZA

Description:
Can you make sense of this file?

Download the file here.

Hints:
1. Multiple decoding is always good.
```
Challenge link: [https://play.picoctf.org/practice/challenge/371](https://play.picoctf.org/practice/challenge/371)

## Solution

One of the tags already gave it away. The contents of the file is [base64 encoded data](https://en.wikipedia.org/wiki/Base64).  
Otherwise, a good indicator for base64 encoded data is a string ending with one or two equal signs ('=')
and that the string contains nothing but letters and numbers (with three exceptions: '+', '/', and '='). The ('=') is padding in base64 encoding.

The contents of the file is
```
VmpGU1EyRXlUWGxTYmxKVVYwZFNWbGxyV21GV1JteDBUbFpPYWxKdFVsaFpWVlUxWVZaS1ZWWnVh
RmRXZWtab1dWWmtSMk5yTlZWWApiVVpUVm10d1VWZFdVa2RpYlZaWFZtNVdVZ3BpU0VKeldWUkNk
MlZXVlhoWGJYQk9VbFJXU0ZkcVRuTldaM0JZVWpGS2VWWkdaSGRXCk1sWnpWV3hhVm1KRk5XOVVW
VkpEVGxaYVdFMVhSbFZhTTBKUFdXdGtlbVF4V2tkWGJYUllDbUY2UWpSWmEyaFRWakpHZEdWRlZs
aGkKYlRrelZERldUMkpzUWxWTlJYTkxDZz09Cg==
```

Both the challenge name and the hint suggests that we need to do a number of decoding levels to get our flag.  
We probably could get away with manually applying a number of ['From Base64' recipes in CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)) but let's write a little Python script called `solve.py` instead that automatically finds the flag in any number of base64 layers.
```python
#!/usr/bin/python

import base64

# Read the encoded flag
with open("enc_flag", 'r') as fh:
    enc_flag = fh.read()

while ('picoCTF' not in enc_flag):
    enc_flag = base64.b64decode(enc_flag).decode('ascii')

print(enc_flag)
```

Then make the script executable and run it
```
┌──(kali㉿kali)-[/picoCTF/picoCTF_2023/General_Skills/repetitions]
└─$ chmod +x solve.py

┌──(kali㉿kali)-[/picoCTF/picoCTF_2023/General_Skills/repetitions]
└─$ ./solve.py       
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

## References

- [Wikipedia - Base64](https://en.wikipedia.org/wiki/Base64)
