# Codebook

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: Beginner picoMini 2022, General Skills, shell, Python
Author: LT 'SYREAL' JONES
  
Description:
Run the Python script code.py in the same directory as codebook.txt.

Download code.py
Download codebook.txt

Hints:
1. On the webshell, use ls to see if both files are in the directory you are in
2. The str_xor function does not need to be reverse engineered for this challenge.
```

## Solution

Most of the time you make sure the script is executable and then run it
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/Codebook]
└─$ chmod +x code.py                                                        

┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/Codebook]
└─$ ./code.py 
./code.py: 2: import: not found
./code.py: 3: import: not found
./code.py: 7: Syntax error: "(" unexpected
``` 

But in this case that doesn't work. The reason for this is that the script doesn't comtain a so called 'shebang' - a comment specifying what king of program/interpreter that should execute the script. It normally look something like this `#!/usr/bin/python3`.

Lets check the first lines of the script with `head`
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/Codebook]
└─$ head code.py 

import random
import sys

def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
```

We need to explicitly say that Python should run the script like this
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/Codebook]
└─$ python code.py 
picoCTF{<REDACTED>}
```

For additional information, please see the references below.

### References

- [Real Python - Executing Python Scripts With a Shebang](https://realpython.com/python-shebang/)
