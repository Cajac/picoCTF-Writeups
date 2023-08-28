# Lets Warm Up

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 50
Tags: picoCTF 2019, General Skills
Author: SANJAY C/DANNY TUNITIS
  
Description:
If I told you a word started with 0x70 in hexadecimal, what would it start with in ASCII?
 
Hints:
1. Submit your answer in our flag format. For example, if your answer was 'hello', 
   you would submit 'picoCTF{hello}' as the flag.
```

## Solution

We can either manually lookup the answer is an [ASCII table](https://www.ascii-code.com/) or use an interactive Python session to do the work for us with the [chr function](https://docs.python.org/3/library/functions.html#chr)
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/picoCTF_2019/General_Skills/Lets_Warm_Up]
└─$ python                
Python 3.11.4 (main, Jun  7 2023, 10:13:09) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print('picoCTF{' + chr(0x70) + '}') 
picoCTF{p}
>>> exit()
```

For additional information, please see the references below.

## References

- [Wikipredia - ASCII](https://en.wikipedia.org/wiki/ASCII)
- [ASCII Table](https://www.ascii-code.com/)
