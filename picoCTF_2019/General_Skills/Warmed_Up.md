# Warmed Up

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 50
Tags: picoCTF 2019, General Skills
Author: SANJAY C/DANNY TUNITIS

Description:
What is 0x3D (base 16) in decimal (base 10)?

Hints:
1. Submit your answer in our flag format. For example, if your answer was '22', 
   you would submit 'picoCTF{22}' as the flag.
```

## Solution

We can use an interactive Python session to do the work for us with the [str function](https://docs.python.org/3/library/functions.html#func-str) and the fact that Python understands [hexadecimal numbers](https://en.wikipedia.org/wiki/Hexadecimal)
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/General_Skills/Warmed_Up]
└─$ python
Python 3.11.4 (main, Jun  7 2023, 10:13:09) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print('picoCTF{' + str(0x3d) + '}')
picoCTF{61}
>>> exit()
```

For additional information, please see the references below.

## References

- [Wikipredia - Hexadecimal](https://en.wikipedia.org/wiki/Hexadecimal)
