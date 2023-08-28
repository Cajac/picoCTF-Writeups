# 2Warm

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 50
Tags: picoCTF 2019, General Skills
Author: SANJAY C/DANNY TUNITIS

Description:
Can you convert the number 42 (base 10) to binary (base 2)?

Hints:
1. Submit your answer in our competition's flag format. For example, if your answer was '11111', 
   you would submit 'picoCTF{11111}' as the flag.
```

## Solution

We can use an interactive Python session to do the work for us with the [bin function](https://docs.python.org/3/library/functions.html#bin)
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/General_Skills/2Warm]
└─$ python
Python 3.11.4 (main, Jun  7 2023, 10:13:09) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print('picoCTF{' + bin(42)[2:] + '}')
picoCTF{101010}
>>> exit()
```

For additional information, please see the references below.

## References

- [Wikipredia - Binary number](https://en.wikipedia.org/wiki/Binary_number)
- [Python - Slicing Strings](https://www.w3schools.com/python/python_strings_slicing.asp)
