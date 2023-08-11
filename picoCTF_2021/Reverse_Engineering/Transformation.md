# Transformation

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 20
Tags: picoCTF 2021, Reverse Engineering
Author: MADSTACKS

Description:
I wonder what this really is... enc 

''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])

Hints:
1. You may find some decoders online
```

## Solution

### Analyze the given information

Lets start by looking at what we have.

We have an encoded file
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Reverse_Engineering/Transformation]
└─$ cat enc                              
灩捯䍔䙻ㄶ形楴獟楮獴㌴摟潦弸弲㘶㠴挲ぽ  
```
that looks like Chinese when viewed with UTF-8 encoding.

We also have the Python code snippet that encoded the data. It uses list comprehension, the `<<` (left bitwise shift) operator and the `ord` and `chr` functions to encode the flag as a 16-bit string.

### CyberChef solution

As the hint suggested you can use an online site such as [CyberChef](https://gchq.github.io/CyberChef/) and the 'Encode text' recipe to get the flag. 

Enter 'text' in the `Operations` search bar, then drag and drop `Encode text` to the `Recipe`.  
Change the Encoding to `UTF-16BE (1201)`, copy the scrambled flag to the `Input` pane and press `BAKE`.

The flag will be shown in the `Output` pane.

### Python solution

Alternatively, we can put together a Python script that reverses what was done. Something like this
```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

enc_flag = '灩捯䍔䙻ㄶ形楴獟楮獴㌴摟潦弸弲㘶㠴挲ぽ'    

flag = ''
for i in range(0, len(enc_flag)):
    flag += chr(ord(enc_flag[i]) >> 8)
    flag += chr(ord(enc_flag[i]) - ((ord(enc_flag[i])>>8)<<8))
print(flag)
```

Then, make sure the script is executable and run it to get the flag
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Reverse_Engineering/Transformation]
└─$ chmod +x solve.py 

┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2021/Reverse_Engineering/Transformation]
└─$ ./solve.py
picoCTF{<REDACTED>}
```

### References

- [Programiz - Python List Comprehension](https://www.programiz.com/python-programming/list-comprehension)
- [Python - Bitwise Operators](https://wiki.python.org/moin/BitwiseOperators)
- [Digital Ocean - Python ord(), chr() functions](https://www.digitalocean.com/community/tutorials/python-ord-chr)
