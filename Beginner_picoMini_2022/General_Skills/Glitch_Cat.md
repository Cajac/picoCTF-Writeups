# Glitch Cat

- [Challenge information](#challenge-information)
- [Solution](#solution)
- [References](#references)

## Challenge information
```
Points: 100
Tags: Beginner picoMini 2022, General Skills, nc, shell, Python
Author: LT 'SYREAL' JONES

Description:
Our flag printing service has started glitching!

$ nc saturn.picoctf.net 50363

Hints:
1. ASCII is one of the most common encodings used in programming
2. We know that the glitch output is valid Python, somehow!
3. Press Ctrl and c on your keyboard to close your connection and return to the command prompt.
```
Challenge link: [https://play.picoctf.org/practice/challenge/242](https://play.picoctf.org/practice/challenge/242)

## Solution

Connect to the flag printing service
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/Glitch_Cat]
└─$ nc saturn.picoctf.net 50363
'picoCTF{gl17ch_m3_n07_' + chr(0x61) + chr(0x34) + chr(0x33) + chr(0x39) + chr(0x32) + chr(0x64) + chr(0x32) + chr(0x65) + '}'
```

The first part of the flag looks correct, but the last part looks rather like python code.

Let's try to execute it
```bash
┌──(kali㉿kali)-[/mnt/…/picoCTF/Beginner_picoMini_2022/General_Skills/Glitch_Cat]
└─$ python -c "print('picoCTF{gl17ch_m3_n07_' + chr(0x61) + chr(0x34) + chr(0x33) + chr(0x39) + chr(0x32) + chr(0x64) + chr(0x32) + chr(0x65) + '}')"
picoCTF{<REDACTED>}
```
And we get the complete flag (but redacted here).  

The plus operator can also "add" strings together. This is called concatenation.  
The `chr` function returns the ASCII-character of the value.  
Numbers preceded with '0x' are in hexadecimal.

For additional information, please see the references below.

### References

- [W3Schools - Python Operators](https://www.w3schools.com/python/python_operators.asp)
- [nc - Linux man page](https://linux.die.net/man/1/nc)
- [Wikipedia - ASCII](https://en.wikipedia.org/wiki/ASCII)
- [Wikipedia - Hexadecimal](https://en.wikipedia.org/wiki/Hexadecimal)
